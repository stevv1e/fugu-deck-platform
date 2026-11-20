package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeSpaces struct {
	m         map[string]SpaceInfo
	deleteSig string
}

func (f *fakeSpaces) Get(_ context.Context, name string) (SpaceInfo, error) {
	s, ok := f.m[name]
	if !ok {
		return SpaceInfo{}, ErrNotFound
	}
	return s, nil
}

func (f *fakeSpaces) Ensure(_ context.Context, name, owner, key string) error {
	s := f.m[name]
	s.Name, s.Owner, s.TokenKey = name, owner, key
	f.m[name] = s
	return nil
}

func (f *fakeSpaces) EnsureTeam(ctx context.Context, name, owner, _ string, key string) error {
	return f.Ensure(ctx, name, owner, key)
}

func (f *fakeSpaces) List(_ context.Context) ([]SpaceInfo, error) {
	out := []SpaceInfo{}
	for _, s := range f.m {
		out = append(out, s)
	}
	return out, nil
}

// SetSuspended ведёт себя как кластер: флаг ставится сразу, а фазу оператор меняет позже (в тестах — вручную).
func (f *fakeSpaces) SetSuspended(_ context.Context, name string, v bool) error {
	s, ok := f.m[name]
	if !ok {
		return ErrNotFound
	}
	s.Suspended = v
	f.m[name] = s
	return nil
}

func (f *fakeSpaces) SetWakeAt(_ context.Context, name string, at time.Time) error {
	s, ok := f.m[name]
	if !ok {
		return ErrNotFound
	}
	s.WakeAt = at
	f.m[name] = s
	return nil
}

func (f *fakeSpaces) SetOwner(_ context.Context, name, owner string) error {
	s, ok := f.m[name]
	if !ok {
		return ErrNotFound
	}
	s.Owner = owner
	f.m[name] = s
	return nil
}

func (f *fakeSpaces) SetInactiveDelete(_ context.Context, name string, on bool) error {
	s, ok := f.m[name]
	if !ok {
		return ErrNotFound
	}
	s.InactiveDelete = on
	f.m[name] = s
	return nil
}

func (f *fakeSpaces) RequestDelete(_ context.Context, name, jws string, _ time.Time) error {
	s, ok := f.m[name]
	if !ok {
		return ErrNotFound
	}
	s.DeleteRequested = jws != ""
	if jws == "" {
		s.DeleteAt, s.DeleteError = "", ""
	}
	f.m[name] = s
	f.deleteSig = jws
	return nil
}

// spaceStand — стенд входа на api плюс «агент» пространства, который проверяет токен control-plane так же,
// как backend/app/spaceauth.py: подпись ES256 публичным ключом из аннотации Space, iss, aud, срок.
type spaceStand struct {
	*authStand
	sp    *fakeSpaces
	agent *httptest.Server
	seen  []*http.Request
}

func newSpaceStand(t *testing.T) *spaceStand {
	t.Helper()
	st := &spaceStand{authStand: newAuthStand(t), sp: &fakeSpaces{m: map[string]SpaceInfo{}}}
	st.agent = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.seen = append(st.seen, r.Clone(context.Background()))
		pub := st.sp.m["anna"].TokenKey
		blk, _ := pem.Decode([]byte(pub))
		if blk == nil {
			http.Error(w, "нет ключа", 500)
			return
		}
		pk, _ := x509.ParsePKIXPublicKey(blk.Bytes)
		_, cl, err := verifyJWS(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), func(map[string]any) (crypto.PublicKey, error) { return pk, nil })
		if err != nil || cl["iss"] != "deck-control-plane" || cl["aud"] != "space:anna" || cl["role"] != "owner" {
			http.Error(w, "токен пространства не принят", 401)
			return
		}
		if r.URL.Path == "/api/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			f := w.(http.Flusher)
			for i := 0; i < 3; i++ {
				io.WriteString(w, "data: кусок\n\n")
				f.Flush()
				time.Sleep(40 * time.Millisecond)
			}
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"sub": cl["sub"], "path": r.URL.Path, "query": r.URL.RawQuery})
	}))
	t.Cleanup(st.agent.Close)
	u, _ := url.Parse(st.agent.URL)
	st.s.Spaces = st.sp
	st.s.SpaceURL = func(string) *url.URL { return u }
	return st
}

func TestSpaceCreateAndProxy(t *testing.T) {
	st := newSpaceStand(t)
	if w := st.req("GET", "/v1/space", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"exists":false`) {
		t.Fatalf("до создания: %d %s", w.Code, w.Body)
	}
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 404 {
		t.Fatalf("несуществующее пространство: %d", w.Code)
	}
	w := st.req("POST", "/v1/space", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"phase":"Pending"`) || !strings.Contains(w.Body.String(), `"url":"https://api.deck.test/s/anna"`) {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	if !strings.HasPrefix(st.sp.m["anna"].TokenKey, "-----BEGIN PUBLIC KEY-----") || st.sp.m["anna"].Owner != "anna" {
		t.Fatalf("в Space не записан ключ токенов: %+v", st.sp.m["anna"])
	}
	// оператор ещё не поднял агента
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("не готовое пространство: %d", w.Code)
	}
	ready := st.sp.m["anna"]
	ready.Phase, ready.Namespace = "Ready", "deck-u-anna"
	st.sp.m["anna"] = ready

	// Служебные адреса агента через control-plane недоступны.
	before := len(st.seen)
	for _, p := range []string{"/s/anna/internal/backup", "/s/anna/internal/restore", "/s/anna/internal"} {
		if w := st.req("GET", p, "", nil); w.Code != 404 || len(st.seen) != before {
			t.Fatalf("%s: %d, дошло до агента: %v", p, w.Code, len(st.seen) != before)
		}
	}

	w = st.req("POST", "/s/anna/api/projects?x=1&access_token=CLIENT", `{"a":1}`, func(r *http.Request) {
		r.Header.Set("Cookie", "deck_invite=x")
		r.Header.Set("X-Deck-Invite-Nick", "admin")
	})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"sub":"anna"`) || !strings.Contains(w.Body.String(), `"path":"/api/projects"`) {
		t.Fatalf("запрос в пространство: %d %s", w.Code, w.Body)
	}
	got := st.seen[len(st.seen)-1]
	if strings.Contains(got.URL.RawQuery, "access_token") || got.URL.Query().Get("x") != "1" {
		t.Errorf("параметры запроса: %q", got.URL.RawQuery)
	}
	for _, h := range []string{"Dpop", "Cookie", certHeader, "X-Deck-Invite-Nick"} {
		if got.Header.Get(h) != "" {
			t.Errorf("в пространство ушёл заголовок %s", h)
		}
	}
	if strings.Contains(got.Header.Get("Authorization"), "DPoP") {
		t.Error("в пространство ушёл токен Keycloak")
	}

	// агент недоступен (перезапуск) — 503 с Retry-After, а не 502: клиент повторит
	good := st.s.SpaceURL
	st.s.SpaceURL = func(string) *url.URL { return &url.URL{Scheme: "http", Host: "127.0.0.1:1"} }
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("агент недоступен: %d", w.Code)
	}
	st.s.SpaceURL = good

	// чужой ключ токенов в Space (создано не этим control-plane): запрос не уходит агенту, ключ исправляется
	n0 := len(st.seen)
	foreign := ready
	foreign.TokenKey = "-----BEGIN PUBLIC KEY-----\nчужой\n-----END PUBLIC KEY-----\n"
	st.sp.m["anna"] = foreign
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 503 || len(st.seen) != n0 {
		t.Fatalf("чужой ключ: %d", w.Code)
	}
	if st.sp.m["anna"].TokenKey != ready.TokenKey {
		t.Fatal("ключ токенов в Space не исправлен")
	}
	st.sp.m["anna"] = foreign
	if w := st.req("GET", "/v1/space", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"phase":"Pending"`) || st.sp.m["anna"].TokenKey != ready.TokenKey {
		t.Fatalf("GET /v1/space с чужим ключом: %d %s", w.Code, w.Body)
	}
	heal := st.sp.m["anna"]
	heal.Phase, heal.Namespace = "Ready", "deck-u-anna"
	st.sp.m["anna"] = heal

	// поток (SSE) доходит без буферизации и целиком
	w = st.req("GET", "/s/anna/api/stream", "", nil)
	if w.Code != 200 || strings.Count(w.Body.String(), "data: кусок") != 3 || !w.Flushed {
		t.Fatalf("поток: %d %q flushed=%v", w.Code, w.Body.String(), w.Flushed)
	}

	// чужое пространство выглядит как несуществующее — даже если оно есть и готово
	st.sp.m["bob"] = SpaceInfo{Name: "bob", Owner: "bob", Phase: "Ready", Namespace: "deck-u-bob", TokenKey: ready.TokenKey}
	n := len(st.seen)
	if w := st.req("GET", "/s/bob/api/projects", "", nil); w.Code != 404 || len(st.seen) != n {
		t.Fatalf("чужое пространство: %d", w.Code)
	}
	// Space с именем пользователя, но чужим владельцем или чужим namespace — не обслуживается
	hijack := ready
	hijack.Owner = "bob"
	st.sp.m["anna"] = hijack
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 404 {
		t.Errorf("Space с чужим владельцем: %d", w.Code)
	}
	hijack = ready
	hijack.Namespace = "deck-keys"
	st.sp.m["anna"] = hijack
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 503 || len(st.seen) != n+0 {
		t.Errorf("Space с чужим namespace: %d", w.Code)
	}
	st.sp.m["anna"] = ready

	// без входа на api в пространство не попасть, через join — тоже
	if w := st.req("GET", "/s/anna/api/projects", "", func(r *http.Request) { r.Header.Del("DPoP") }); w.Code != 401 {
		t.Errorf("без DPoP: %d", w.Code)
	}
	if w := st.req("GET", "/s/anna/api/projects", "", func(r *http.Request) { r.Host = "join.deck.test" }); w.Code != 404 {
		t.Errorf("через join: %d", w.Code)
	}
	if w := st.req("DELETE", "/v1/space", "", nil); w.Code != 405 {
		t.Errorf("DELETE /v1/space: %d", w.Code)
	}
}

func TestSpaceTokenClaims(t *testing.T) {
	st := newSpaceStand(t)
	tok, err := st.s.spaceToken("anna", "anna", "owner")
	if err != nil {
		t.Fatal(err)
	}
	_, pub, _ := st.s.signer()
	blk, _ := pem.Decode([]byte(pub))
	pk, _ := x509.ParsePKIXPublicKey(blk.Bytes)
	h, cl, err := verifyJWS(tok, func(map[string]any) (crypto.PublicKey, error) { return pk, nil })
	if err != nil || h["alg"] != "ES256" {
		t.Fatalf("подпись: %v", err)
	}
	if cl["iss"] != "deck-control-plane" || cl["aud"] != "space:anna" || cl["sub"] != "anna" || cl["role"] != "owner" ||
		int64(cl["exp"].(float64))-int64(cl["iat"].(float64)) != 600 {
		t.Fatalf("поля токена: %v", cl)
	}
	// ключ один на всё время жизни хранилища
	_, pub2, _ := st.s.signer()
	if pub != pub2 {
		t.Fatal("ключ токенов сменился между вызовами")
	}
}
