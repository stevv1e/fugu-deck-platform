package controlplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeKG struct {
	calls  []string
	bodies [][]byte
	status int
	resp   string
	err    error
	byPath map[string]string // ответ 200 для конкретного пути keyguard (важнее resp)
}

func (f *fakeKG) Post(_ context.Context, path string, body []byte) (int, []byte, error) {
	f.calls, f.bodies = append(f.calls, path), append(f.bodies, body)
	if f.err != nil {
		return 0, nil, f.err
	}
	if r, ok := f.byPath[path]; ok {
		return 200, []byte(r), nil
	}
	return f.status, []byte(f.resp), nil
}

type fakeDir struct {
	users           []string
	deleted         []string
	passkeysRemoved []string
	err             error
}

func (f *fakeDir) DeleteUser(_ context.Context, nick string) error {
	if f.err != nil {
		return f.err
	}
	f.deleted = append(f.deleted, nick)
	return nil
}

func (f *fakeDir) RemovePasskeys(_ context.Context, nick string) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.passkeysRemoved = append(f.passkeysRemoved, nick)
	return 1, nil
}

func (f *fakeDir) EnsureUser(_ context.Context, nick string) error {
	if f.err != nil {
		return f.err
	}
	f.users = append(f.users, nick)
	return nil
}

type stand struct {
	s   *Server
	kg  *fakeKG
	dir *fakeDir
	now time.Time
}

func newStand() *stand {
	st := &stand{kg: &fakeKG{status: 200, resp: `{"device_id":"d-1","status":"pending"}`}, dir: &fakeDir{},
		now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	st.s = &Server{
		Cfg: Config{APIURL: "https://api.deck.test", JoinURL: "https://join.deck.test", Issuer: "https://id.deck.test/realms/deck",
			HPKEPub: "BHPKE", CookieDomain: "deck.test", InviteTTL: 24 * time.Hour, GateTTL: 30 * time.Minute},
		Store: NewMemStore(), KG: st.kg, Users: st.dir, Now: func() time.Time { return st.now }, Log: log.New(io.Discard, "", 0),
	}
	return st
}

func (st *stand) invite(t *testing.T, nick string) string {
	t.Helper()
	link, _, err := st.s.NewInvite(context.Background(), nick, "admin")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	return u.Query().Get("invite")
}

func jwtFor(user string) string {
	p, _ := json.Marshal(map[string]string{"preferred_username": user})
	return "e30." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

func do(h http.Handler, method, target string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestInviteLink(t *testing.T) {
	st := newStand()
	link, exp, err := st.s.NewInvite(context.Background(), "anna", "admin")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	q := u.Query()
	if u.Scheme != "fugudeck" || u.Host != "join" || q.Get("api") != "https://api.deck.test" || q.Get("iss") != "https://id.deck.test/realms/deck" ||
		q.Get("join") != "https://join.deck.test" || q.Get("hpke") != "BHPKE" || !inviteRe.MatchString(q.Get("invite")) {
		t.Fatalf("ссылка: %s", link)
	}
	if !exp.Equal(st.now.Add(24 * time.Hour)) {
		t.Fatalf("срок: %v", exp)
	}
	if len(st.dir.users) != 1 || st.dir.users[0] != "anna" {
		t.Fatalf("пользователь в Keycloak не создан: %v", st.dir.users)
	}
	// в хранилище — только хеш токена
	if _, err := st.s.Store.Invite(q.Get("invite")); !errors.Is(err, ErrNotFound) {
		t.Fatal("токен приглашения лежит в хранилище открытым")
	}
}

func TestNickRules(t *testing.T) {
	st := newStand()
	for _, bad := range []string{"", "ab", "Anna", "анна", "an na", "a/b", "../x", "-anna", "anna-", "an--na", "anna.b", strings.Repeat("a", 34), "admin​"} {
		if _, _, err := st.s.NewInvite(context.Background(), bad, "admin"); !errors.Is(err, ErrBadNick) {
			t.Errorf("ник %q принят", bad)
		}
	}
	if len(st.dir.users) != 0 {
		t.Fatal("для недопустимого ника создан пользователь")
	}
	for _, ok := range []string{"anna", "bob-2", "a1b", strings.Repeat("a", 32)} {
		if _, _, err := st.s.NewInvite(context.Background(), ok, "admin"); err != nil {
			t.Errorf("ник %q отклонён: %v", ok, err)
		}
	}
}

func TestInviteNotIssuedWhenKeycloakFails(t *testing.T) {
	st := newStand()
	st.dir.err = errors.New("keycloak лежит")
	w := do(st.s.AdminHandler(), "POST", "/admin/v1/invites", nil, `{"nick":"anna"}`)
	if w.Code != 502 {
		t.Fatalf("код %d", w.Code)
	}
	if w := do(st.s.AdminHandler(), "POST", "/admin/v1/invites", nil, `{"nick":"An"}`); w.Code != 400 {
		t.Fatalf("недопустимый ник: код %d", w.Code)
	}
}

func TestStart(t *testing.T) {
	st := newStand()
	tok := st.invite(t, "anna")
	h := st.s.PublicHandler()
	next := "https://id.deck.test/realms/deck/protocol/openid-connect/auth?client_id=deck-app"
	target := func(tok, next string) string {
		return "/start?" + url.Values{"invite": {tok}, "next": {next}}.Encode()
	}

	w := do(h, "GET", target(tok, next), nil, "")
	if w.Code != 302 || w.Header().Get("Location") != next {
		t.Fatalf("код %d, Location %q", w.Code, w.Header().Get("Location"))
	}
	c := w.Result().Cookies()
	if len(c) != 2 || c[0].Name != "deck_invite" || !c[0].Secure || !c[0].HttpOnly || c[0].Domain != "deck.test" || c[0].MaxAge != 1800 {
		t.Fatalf("cookie: %+v", c)
	}
	if c[1].Name != pairCookie || c[1].Value != "" || c[1].MaxAge >= 0 {
		t.Fatalf("обычный вход не стёр pairing cookie: %+v", c[1])
	}
	if strings.Contains(c[0].Value, tok) {
		t.Fatal("в cookie лежит сам токен приглашения")
	}

	for name, bad := range map[string]string{
		"чужой сайт":            "https://evil.example/realms/deck/x",
		"похожий хост":          "https://id.deck.test.evil.example/realms/deck/x",
		"другой realm":          "https://id.deck.test/realms/master/x",
		"http":                  "http://id.deck.test/realms/deck/x",
		"префикс без косой":     "https://id.deck.test/realms/deck-evil/x",
		"пустой":                "",
		"путь с подменой хоста": "https://id.deck.test@evil.example/realms/deck/x",
	} {
		if w := do(h, "GET", target(tok, bad), nil, ""); w.Code != 400 || len(w.Result().Cookies()) != 0 {
			t.Errorf("next %s: код %d", name, w.Code)
		}
	}
	// чужой токен: первый символ заменён на заведомо другой (при замене на постоянный тест падал бы раз из 64)
	other := "A" + tok[1:]
	if tok[0] == 'A' {
		other = "B" + tok[1:]
	}
	if w := do(h, "GET", target(other, next), nil, ""); w.Code != 403 {
		t.Errorf("чужой токен: код %d", w.Code)
	}
	if w := do(h, "POST", target(tok, next), nil, ""); w.Code != 405 {
		t.Errorf("POST: код %d", w.Code)
	}
	st.now = st.now.Add(24 * time.Hour)
	if w := do(h, "GET", target(tok, next), nil, ""); w.Code != 403 {
		t.Errorf("истёкшее приглашение: код %d", w.Code)
	}
}

func TestGate(t *testing.T) {
	st := newStand()
	tok := st.invite(t, "anna")
	auth := st.s.AuthHandler()

	if w := do(auth, "GET", "/auth/invite", nil, ""); w.Code != 401 {
		t.Fatalf("без приглашения: %d", w.Code)
	}
	w := do(auth, "GET", "/auth/invite", map[string]string{"X-Deck-Invite": tok}, "")
	if w.Code != 200 || w.Header().Get("X-Deck-Invite-Nick") != "anna" {
		t.Fatalf("токен в заголовке: %d %q", w.Code, w.Header().Get("X-Deck-Invite-Nick"))
	}
	// клиент не может назначить себе ник
	w = do(auth, "GET", "/auth/invite", map[string]string{"X-Deck-Invite-Nick": "admin"}, "")
	if w.Code != 401 {
		t.Fatalf("подставной ник: %d", w.Code)
	}

	// cookie от /start
	sw := do(st.s.PublicHandler(), "GET", "/start?"+url.Values{"invite": {tok}, "next": {"https://id.deck.test/realms/deck/x"}}.Encode(), nil, "")
	ck := sw.Result().Cookies()[0]
	cookie := func(v string) map[string]string { return map[string]string{"Cookie": "deck_invite=" + v} }
	if w := do(auth, "GET", "/auth/invite", cookie(ck.Value), ""); w.Code != 200 || w.Header().Get("X-Deck-Invite-Nick") != "anna" {
		t.Fatalf("cookie: %d", w.Code)
	}
	parts := strings.Split(ck.Value, ".")
	for name, v := range map[string]string{
		"чужой ник":      "admin." + parts[1] + "." + parts[2],
		"продлённый":     parts[0] + ".9999999999." + parts[2],
		"без подписи":    parts[0] + "." + parts[1] + ".",
		"мусор":          "x",
		"лишний сегмент": ck.Value + ".x",
	} {
		if w := do(auth, "GET", "/auth/invite", cookie(v), ""); w.Code != 401 {
			t.Errorf("cookie %s принята", name)
		}
	}
	st.now = st.now.Add(31 * time.Minute)
	if w := do(auth, "GET", "/auth/invite", cookie(ck.Value), ""); w.Code != 401 {
		t.Error("cookie принята после 30 минут")
	}
	// ключ другого экземпляра не подходит
	other := newStand()
	otherTok := other.invite(t, "anna")
	ow := do(other.s.PublicHandler(), "GET", "/start?"+url.Values{"invite": {otherTok}, "next": {"https://id.deck.test/realms/deck/x"}}.Encode(), nil, "")
	st.now = other.now
	if w := do(auth, "GET", "/auth/invite", cookie(ow.Result().Cookies()[0].Value), ""); w.Code != 401 {
		t.Error("принята cookie, подписанная чужим ключом")
	}
}

func TestEnroll(t *testing.T) {
	st := newStand()
	tok := st.invite(t, "anna")
	h := st.s.PublicHandler()
	inv := map[string]string{"X-Deck-Invite": tok}
	body := `{"access_token":"` + jwtFor("anna") + `","csr":"x"}`

	if w := do(h, "POST", "/v1/enroll/challenge", nil, "{}"); w.Code != 401 {
		t.Fatalf("вызов без приглашения: %d", w.Code)
	}
	// заголовок ника от клиента (на api.<домен> forwardAuth нет) приглашения не заменяет
	if w := do(h, "POST", "/v1/enroll", map[string]string{"X-Deck-Invite-Nick": "anna"}, body); w.Code != 401 {
		t.Fatalf("регистрация по подставному нику: %d", w.Code)
	}
	if len(st.kg.calls) != 0 {
		t.Fatal("запрос без приглашения дошёл до keyguard")
	}

	st.kg.resp = `{"challenge":"abc"}`
	if w := do(h, "POST", "/v1/enroll/challenge", inv, "{}"); w.Code != 200 || w.Body.String() != `{"challenge":"abc"}` || st.kg.calls[0] != "/v1/devices/challenge" {
		t.Fatalf("вызов: %d %s %v", w.Code, w.Body, st.kg.calls)
	}

	// приглашение для anna, токен — mallory
	if w := do(h, "POST", "/v1/enroll", inv, `{"access_token":"`+jwtFor("mallory")+`"}`); w.Code != 403 {
		t.Fatalf("чужой пользователь: %d", w.Code)
	}
	for _, bad := range []string{`{}`, `{"access_token":"x"}`, `{"access_token":"a.b.c"}`, `не json`} {
		if w := do(h, "POST", "/v1/enroll", inv, bad); w.Code != 403 {
			t.Errorf("тело %q: %d", bad, w.Code)
		}
	}
	if len(st.kg.calls) != 1 {
		t.Fatal("отклонённая регистрация дошла до keyguard")
	}

	// keyguard отказал — приглашение не сгорает
	st.kg.status, st.kg.resp = 403, `{"error":"токен: истёк"}`
	if w := do(h, "POST", "/v1/enroll", inv, body); w.Code != 403 || !strings.Contains(w.Body.String(), "истёк") {
		t.Fatalf("отказ keyguard: %d %s", w.Code, w.Body)
	}
	st.kg.status, st.kg.resp = 200, `{"device_id":"d-1","status":"pending"}`
	w := do(h, "POST", "/v1/enroll", inv, body)
	if w.Code != 200 || !bytes.Equal(st.kg.bodies[len(st.kg.bodies)-1], []byte(body)) {
		t.Fatalf("регистрация: %d; тело в keyguard изменено", w.Code)
	}
	// одноразовость
	if w := do(h, "POST", "/v1/enroll", inv, body); w.Code != 403 {
		t.Fatalf("вторая регистрация по тому же приглашению: %d", w.Code)
	}
	// использованное приглашение не даёт и вызов для аттестации: иначе приложение сочло бы его действующим
	n := len(st.kg.calls)
	if w := do(h, "POST", "/v1/enroll/challenge", inv, "{}"); w.Code != 403 || len(st.kg.calls) != n {
		t.Fatalf("вызов по использованному приглашению: %d", w.Code)
	}
	// использованное приглашение в браузер больше не пускает
	if w := do(h, "GET", "/start?"+url.Values{"invite": {tok}, "next": {"https://id.deck.test/realms/deck/x"}}.Encode(), nil, ""); w.Code != 403 {
		t.Fatalf("/start с использованным приглашением: %d", w.Code)
	}
	if w := do(h, "GET", "/v1/enroll", inv, ""); w.Code != 405 {
		t.Fatalf("GET: %d", w.Code)
	}
	fresh := map[string]string{"X-Deck-Invite": st.invite(t, "bob")}
	if w := do(h, "POST", "/v1/enroll/challenge", fresh, strings.Repeat("x", 300<<10)); w.Code != 413 {
		t.Fatalf("большое тело: %d", w.Code)
	}
	st.now = st.now.Add(25 * time.Hour)
	if w := do(h, "POST", "/v1/enroll/challenge", fresh, `{}`); w.Code != 401 {
		t.Fatalf("истёкшее приглашение: %d", w.Code)
	}
}

// Статус устройства: приглашение не нужно (устройство ждёт подтверждения дольше, чем оно живёт) — запрос
// подписан ключом сессии, и проверяет его keyguard.
func TestEnrollStatus(t *testing.T) {
	st := newStand()
	h := st.s.PublicHandler()
	st.kg.resp = `{"device_id":"d-1","status":"pending"}`
	w := do(h, "POST", "/v1/enroll/status", nil, `{"device_id":"d-1","proof":"p"}`)
	if w.Code != 200 || st.kg.calls[0] != "/v1/devices/status" || string(st.kg.bodies[0]) != `{"device_id":"d-1","proof":"p"}` {
		t.Fatalf("статус: %d %v", w.Code, st.kg.calls)
	}
	st.kg.status, st.kg.resp = 404, `{"error":"устройство не найдено"}`
	if w := do(h, "POST", "/v1/enroll/status", nil, `{}`); w.Code != 404 {
		t.Fatalf("ответ keyguard не передан: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/enroll/status", nil, strings.Repeat("x", 9<<10)); w.Code != 413 {
		t.Fatalf("большое тело без приглашения: %d", w.Code)
	}
	st.kg.err = errors.New("connection refused")
	if w := do(h, "POST", "/v1/enroll/status", nil, `{}`); w.Code != 502 {
		t.Fatalf("keyguard недоступен: %d", w.Code)
	}
}

func TestUseInviteOnce(t *testing.T) {
	m := NewMemStore()
	m.PutInvite("h", Invite{Nick: "anna"})
	if err := m.UseInvite("h"); err != nil {
		t.Fatal(err)
	}
	if err := m.UseInvite("h"); err == nil {
		t.Fatal("приглашение использовано дважды")
	}
	if err := m.UseInvite("нет"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
