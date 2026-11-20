package keyguard

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------- стенд ----------------

type phone struct {
	dev              *Device
	session, confirm *ecdsa.PrivateKey
}

func newPhone(id, user string) *phone {
	s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &phone{dev: &Device{ID: id, User: user, SessionPub: &s.PublicKey, ConfirmPub: &c.PublicKey}, session: s, confirm: c}
}

var nonceCtr int64

// jwsOf — компактный JWS действия, как его делает приложение (deck.ts, signAction): подпись r||s над "заголовок.payload".
func jwsOf(payload []byte, kid string, key *ecdsa.PrivateKey) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": ActionTyp, "kid": kid})
	in := b64u.EncodeToString(hdr) + "." + b64u.EncodeToString(payload)
	h := sha256.Sum256([]byte(in))
	r, sg, _ := ecdsa.Sign(rand.Reader, key, h[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sg.FillBytes(sig[32:])
	return in + "." + b64u.EncodeToString(sig)
}

func payloadOf(jws string) []byte {
	b, _ := b64u.DecodeString(strings.Split(jws, ".")[1])
	return b
}

// sign — конверт действия, как в приложении: поля типа + space, device_id, nonce, ts (fields могут их переопределить).
func (p *phone) sign(t *testing.T, kg *rig, fields map[string]any, withKey *ecdsa.PrivateKey) SignedAction {
	a := map[string]any{"device_id": p.dev.ID, "nonce": fmt.Sprintf("nonce-%016d", atomic.AddInt64(&nonceCtr, 1)),
		"ts": json.Number(fmt.Sprint(kg.now().Unix()))}
	for k, v := range fields {
		a[k] = v
	}
	// space — только у действий в пространстве (schema.go); тест может задать его сам
	if t, _ := a["type"].(string); actionSchemas[t].inSpace && a["space"] == nil {
		a["space"] = "u-" + p.dev.User
	}
	if withKey == nil {
		withKey = p.confirm
	}
	return SignedAction{JWS: jwsOf(Canonical(a), p.dev.ID, withKey)}
}

type seen struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func (s *seen) add(r *http.Request, b []byte) {
	s.mu.Lock()
	s.reqs = append(s.reqs, r)
	s.body = append(s.body, b)
	s.mu.Unlock()
}
func (s *seen) last() (*http.Request, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		return nil, nil
	}
	return s.reqs[len(s.reqs)-1], s.body[len(s.body)-1]
}
func (s *seen) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.reqs) }

type rig struct {
	t                  *testing.T
	srv                *Server
	ts                 *httptest.Server
	clock              time.Time
	anth, sak, evil    *seen
	validKeys          map[string]bool
	logs               *bytes.Buffer
	anna, bob, mallory *phone
	slow               time.Duration
}

func (k *rig) now() time.Time { return k.clock }

func newRig(t *testing.T) *rig {
	k := &rig{t: t, clock: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), anth: &seen{}, sak: &seen{}, evil: &seen{},
		validKeys: map[string]bool{"sk-ant-ANNA-0123456789": true, "sk-ant-BOB-0123456789": true, "sk-sak-BOB-0123456789": true, "sk-sak-ANNA-0123456789": true},
		logs:      &bytes.Buffer{}}
	auth := func(r *http.Request) string {
		if v := r.Header.Get("x-api-key"); v != "" {
			return v
		}
		return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		k.anth.add(r, b)
		if !k.validKeys[auth(r)] {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"invalid x-api-key"}`))
			return
		}
		if r.Method == "GET" {
			w.Write([]byte(`{"data":[]}`))
			return
		}
		time.Sleep(k.slow)
		var req map[string]any
		json.Unmarshal(b, &req)
		switch req["model"] {
		case "echo-key": // провайдер «по ошибке» возвращает ключ в ответе
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":"bad key %s"}`, auth(r))
		case "no-usage":
			w.Write([]byte(`{"content":[{"type":"text","text":"hi"}]}`))
		default:
			if req["stream"] == true {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1000,\"output_tokens\":1}}}\n\n"))
				w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n"))
				w.Write([]byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":500}}\n\n"))
				if req["metadata"] == nil { // с metadata мок обрывает поток до конца (TestAttack_Accounting)
					w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
				}
				return
			}
			w.Write([]byte(`{"content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1000,"output_tokens":500}}`))
		}
	}))
	sak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		k.sak.add(r, b)
		if !k.validKeys[auth(r)] {
			w.WriteHeader(401)
			return
		}
		if r.Method == "GET" {
			w.Write([]byte(`{"data":[]}`))
			return
		}
		var req map[string]any
		json.Unmarshal(b, &req)
		if req["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
			if so, _ := req["stream_options"].(map[string]any); so != nil && so["include_usage"] == true {
				w.Write([]byte("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2000,\"completion_tokens\":1000}}\n\n"))
			}
			w.Write([]byte("data: [DONE]\n\n"))
			return
		}
		w.Write([]byte(`{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":2000,"completion_tokens":1000}}`))
	}))
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { k.evil.add(r, nil) }))
	t.Cleanup(func() { anth.Close(); sak.Close(); evil.Close() })

	hk, _ := ecdh.P256().GenerateKey(rand.Reader)
	k.anna, k.bob, k.mallory = newPhone("dev-anna", "anna"), newPhone("dev-bob-1", "bob"), newPhone("dev-mallory", "mallory")
	devs := NewDevices()
	for _, p := range []*phone{k.anna, k.bob, k.mallory} {
		devs.Add(p.dev)
	}
	k.srv = &Server{
		Providers: map[string]*Provider{
			"anthropic": {Name: "anthropic", BaseURL: anth.URL, Path: "/v1/messages", ProbePath: "/v1/models", AuthHeader: "x-api-key", Style: "anthropic",
				Prices: map[string]Price{"claude-x": {InPerM: 3, OutPerM: 15}, "echo-key": {InPerM: 3, OutPerM: 15}, "no-usage": {InPerM: 3, OutPerM: 15}}},
			"sakana": {Name: "sakana", BaseURL: sak.URL, Path: "/v1/chat/completions", ProbePath: "/v1/models", AuthHeader: "authorization", Style: "openai",
				Prices: map[string]Price{"fugu-max-v1.0": {InPerM: 2, OutPerM: 6}, "fugu-ultra-v2.0": {InPerM: 5, OutPerM: 30}}},
		},
		Store: NewMemStore(), Verifier: &Verifier{Devices: devs, Nonces: NewNonces(), Now: k.now},
		Auth: StaticAuth{
			"tok-cp":     {"deck-system", "control-plane"},
			"tok-anna":   {"deck-u-anna", "space"},
			"tok-bob":    {"deck-u-bob", "space"},
			"tok-shop":   {"deck-t-shop", "space"},
			"tok-other":  {"deck-t-other", "space"},
			"tok-random": {"deck-system", "space-operator"},
			"tok-ssh":    {"deck-ssh", "ssh-gateway"},
		},
		Ledger: NewLedger(), Grants: NewGrants(), HPKEKey: hk, Upstream: http.DefaultClient,
		Log: log.New(k.logs, "", 0), Now: k.now, MaxBody: 1 << 20, ControlPlane: Caller{"deck-system", "control-plane"},
		ActionVerifiers: map[Caller][]string{
			{"deck-system", "space-operator"}: {"space_delete", "account_delete"},
			{"deck-system", "control-plane"}:  {"invite_create", "role_change"},
			{"deck-ssh", "ssh-gateway"}:       {"ssh_write", "ssh_danger", "server_add", "agent_rights"},
		},
	}
	k.ts = httptest.NewServer(k.srv.Handler())
	t.Cleanup(k.ts.Close)
	return k
}

func (k *rig) do(method, path, tok string, body []byte, hdr map[string]string) (int, string) {
	req, _ := http.NewRequest(method, k.ts.URL+path, bytes.NewReader(body))
	if tok != "" {
		req.Header.Set("x-api-key", tok)
	}
	for a, b := range hdr {
		req.Header.Set(a, b)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		k.t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return r.StatusCode, string(b)
}

// sealedKeyPut — то, что делает телефон: шифрует ключ для keyguard и подписывает действие с хешем шифротекста
// и последними 4 символами ключа (их человек видит на экране подтверждения).
func (k *rig) sealedKeyPut(p *phone, prov, key string, mut func(map[string]any)) (keyPutReq, string) {
	nonce := fmt.Sprintf("nonce-%016d", atomic.AddInt64(&nonceCtr, 1))
	enc, ct, _ := HPKESeal(k.srv.HPKEKey.PublicKey(), []byte(HPKEInfo), []byte(KeyPutAAD(p.dev.ID, prov, nonce)), []byte(key))
	h := sha256.Sum256(append(append([]byte{}, enc...), ct...))
	a := map[string]any{"type": "key_put", "provider": prov, "key_hint": key[len(key)-4:], "ct_sha256": hex.EncodeToString(h[:]),
		"device_id": p.dev.ID, "nonce": nonce, "ts": json.Number(fmt.Sprint(k.now().Unix()))}
	if mut != nil {
		mut(a)
	}
	return keyPutReq{SignedAction{jwsOf(Canonical(a), p.dev.ID, p.confirm)}, base64.StdEncoding.EncodeToString(enc), base64.StdEncoding.EncodeToString(ct)}, nonce
}

func j(v any) []byte { b, _ := json.Marshal(v); return b }

type check struct {
	t    *testing.T
	n, f int
}

func (c *check) ok(name string, cond bool, detail ...any) {
	c.t.Helper()
	if cond {
		c.n++
		c.t.Logf("PASS %s", name)
	} else {
		c.f++
		c.t.Errorf("FAIL %s %v", name, detail)
	}
}

// ---------------- ввод ключа ----------------

func TestAttack_KeyIntake(t *testing.T) {
	k := newRig(t)
	c := &check{t: t}
	put := func(r keyPutReq, tok string) (int, string) { return k.do("POST", "/v1/keys", tok, j(r), nil) }
	const annaKey = "sk-ant-ANNA-0123456789"

	r, _ := k.sealedKeyPut(k.anna, "anthropic", annaKey, nil)
	st, body := put(r, "tok-cp")
	got, _ := k.srv.Store.Get(nil, "anna", "anthropic")
	c.ok("K1 Анна вводит ключ: сохранён под её именем (по устройству), ответ — только маска", st == 200 && got == annaKey && !strings.Contains(body, "ANNA-0123456789") && strings.Contains(body, "…"), st, body)
	st, body = put(r, "tok-cp")
	c.ok("K2 повтор того же запроса (replay) отклонён", st == 403 && strings.Contains(body, "nonce"), st, body)

	r, _ = k.sealedKeyPut(k.anna, "anthropic", annaKey, nil)
	parts := strings.Split(r.JWS, ".")
	var a map[string]any
	json.Unmarshal(payloadOf(r.JWS), &a)
	a["provider"] = "sakana" // control-plane меняет поле после подписи
	r2 := r
	r2.JWS = parts[0] + "." + b64u.EncodeToString(Canonical(a)) + "." + parts[2]
	st, _ = put(r2, "tok-cp")
	c.ok("K3 подмена поля после подписи отклонена", st == 403, st)

	r, _ = k.sealedKeyPut(k.anna, "anthropic", annaKey, nil)
	r.JWS = jwsOf(payloadOf(r.JWS), k.anna.dev.ID, k.anna.session)
	st, _ = put(r, "tok-cp")
	c.ok("K4 подпись ключом СЕССИИ (без Face ID) не принимается", st == 403, st)

	// Мэллори выдаёт себя за устройство Анны: действие с device_id Анны, подпись своим ключом
	r, _ = k.sealedKeyPut(k.anna, "anthropic", annaKey, nil)
	r.JWS = jwsOf(payloadOf(r.JWS), k.anna.dev.ID, k.mallory.confirm)
	st, _ = put(r, "tok-cp")
	_, errM := k.srv.Store.Get(nil, "mallory", "anthropic")
	c.ok("K5 чужое устройство подписывает действие от имени устройства Анны — отклонено", st == 403 && errM != nil, st)
	r, _ = k.sealedKeyPut(k.mallory, "anthropic", annaKey, nil)
	r.JWS = jwsOf(payloadOf(r.JWS), k.anna.dev.ID, k.mallory.confirm)
	st, body = put(r, "tok-cp")
	c.ok("K5b kid заголовка ≠ device_id действия — отклонено", st == 403 && strings.Contains(body, "kid"), st, body)

	// control-plane подменяет шифротекст (свой ключ злоумышленника), подпись Анны оставляет
	r, _ = k.sealedKeyPut(k.anna, "anthropic", annaKey, nil)
	r3, _ := k.sealedKeyPut(k.anna, "anthropic", "sk-ant-BOB-0123456789", nil)
	r.Enc, r.Ct = r3.Enc, r3.Ct
	st, body = put(r, "tok-cp")
	c.ok("K6 подмена шифротекста посредником отклонена", st == 403 && strings.Contains(body, "шифротекст"), st, body)

	// Мэллори берёт шифротекст Анны и подписывает СВОЁ действие с тем же хешем
	ra, _ := k.sealedKeyPut(k.anna, "sakana", "sk-sak-ANNA-0123456789", nil)
	encB, _ := base64.StdEncoding.DecodeString(ra.Enc)
	ctB, _ := base64.StdEncoding.DecodeString(ra.Ct)
	h := sha256.Sum256(append(encB, ctB...))
	rm, _ := k.sealedKeyPut(k.mallory, "sakana", "sk-sak-ANNA-0123456789", func(m map[string]any) { m["ct_sha256"] = hex.EncodeToString(h[:]) })
	rm.Enc, rm.Ct = ra.Enc, ra.Ct
	st, _ = put(rm, "tok-cp")
	_, err := k.srv.Store.Get(nil, "mallory", "sakana")
	c.ok("K7 чужой шифротекст в свой слот не расшифровывается (AAD с device_id)", st == 403 && err != nil, st)

	k.srv.Verifier.Devices.Revoke("dev-bob-1")
	r, _ = k.sealedKeyPut(k.bob, "anthropic", "sk-ant-BOB-0123456789", nil)
	st, body = put(r, "tok-cp")
	c.ok("K8 отозванное устройство не может вводить ключи", st == 403 && strings.Contains(body, "отозвано"), st, body)

	r, _ = k.sealedKeyPut(k.anna, "anthropic", annaKey, func(m map[string]any) {
		m["ts"] = json.Number(fmt.Sprint(k.now().Add(-6 * time.Minute).Unix()))
	})
	st, _ = put(r, "tok-cp")
	c.ok("K9 действие старше 5 минут отклонено", st == 403, st)
	r, _ = k.sealedKeyPut(k.anna, "anthropic", annaKey, func(m map[string]any) {
		m["ts"] = json.Number(fmt.Sprint(k.now().Add(2 * time.Minute).Unix()))
	})
	st, _ = put(r, "tok-cp")
	c.ok("K10 действие «из будущего» отклонено", st == 403, st)

	// неоднозначный JSON: дубликат поля и не-каноничная форма — даже с верной подписью
	r, _ = k.sealedKeyPut(k.anna, "anthropic", annaKey, nil)
	pl := string(payloadOf(r.JWS))
	dup := strings.Replace(pl, `"provider":"anthropic"`, `"provider":"anthropic","provider":"sakana"`, 1)
	st, body = put(keyPutReq{SignedAction{jwsOf([]byte(dup), k.anna.dev.ID, k.anna.confirm)}, r.Enc, r.Ct}, "tok-cp")
	c.ok("K11 дубликат поля в подписанном JSON отклонён (даже с верной подписью)", st == 403 && strings.Contains(body, "дубликат"), st, body)
	sp := strings.Replace(pl, `,"provider"`, `, "provider"`, 1)
	st, _ = put(keyPutReq{SignedAction{jwsOf([]byte(sp), k.anna.dev.ID, k.anna.confirm)}, r.Enc, r.Ct}, "tok-cp")
	c.ok("K12 не-каноничная форма отклонена", st == 403, st)

	r, _ = k.sealedKeyPut(k.anna, "anthropic", annaKey, nil)
	st, _ = put(r, "tok-anna")
	c.ok("K13 пространство (не control-plane) не может вводить ключи", st == 403, st)
	r, _ = k.sealedKeyPut(k.anna, "anthropic", "sk-ant-X\r\nX-Evil:1234", nil) // хвост проходит схему key_hint — проверяется сам ключ
	st, _ = put(r, "tok-cp")
	c.ok("K14 ключ с CR/LF (инъекция заголовка) отклонён", st == 422, st)
	r, _ = k.sealedKeyPut(k.anna, "anthropic", "sk-ant-INVALID-999999", nil)
	st, body = put(r, "tok-cp")
	c.ok("K15 нерабочий ключ отклонён пробным запросом", st == 422 && strings.Contains(body, "отклонил"), st, body)
	r, _ = k.sealedKeyPut(k.anna, "anthropic", annaKey, func(m map[string]any) { m["key_hint"] = "XXXX" })
	st, body = put(r, "tok-cp")
	c.ok("K16 на экране показан другой ключ (key_hint) — отклонено", st == 403 && strings.Contains(body, "key_hint"), st, body)

	// заголовок JWS: чужой typ (например, DPoP-доказательство ключом подтверждения) действием не считается
	r, _ = k.sealedKeyPut(k.anna, "anthropic", annaKey, nil)
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "dpop+jwt", "kid": k.anna.dev.ID})
	in := b64u.EncodeToString(hdr) + "." + strings.Split(r.JWS, ".")[1]
	hh := sha256.Sum256([]byte(in))
	rr, ss, _ := ecdsa.Sign(rand.Reader, k.anna.confirm, hh[:])
	sig := make([]byte, 64)
	rr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	r.JWS = in + "." + b64u.EncodeToString(sig)
	st, _ = put(r, "tok-cp")
	c.ok("K17 JWS с другим typ не принимается как действие", st == 403, st)
	t.Logf("ввод ключа: %d/%d", c.n, c.n+c.f)
}

// ---------------- прокси ----------------

func (k *rig) seed() {
	k.srv.Store.Put(nil, "anna", "anthropic", "sk-ant-ANNA-0123456789")
	k.srv.Store.Put(nil, "anna", "sakana", "sk-sak-ANNA-0123456789")
	k.srv.Store.Put(nil, "bob", "sakana", "sk-sak-BOB-0123456789")
	k.srv.Store.Put(nil, "bob", "anthropic", "sk-ant-BOB-0123456789")
}

func TestAttack_Proxy(t *testing.T) {
	k := newRig(t)
	k.seed()
	c := &check{t: t}
	msg := func(model string, extra string) []byte {
		return []byte(fmt.Sprintf(`{"model":%q,"max_tokens":1000,"messages":[{"role":"user","content":"hi"}]%s}`, model, extra))
	}
	hdrs := map[string]string{"Authorization": "Bearer ATTACKER", "Cookie": "s=1", "X-Forwarded-For": "1.2.3.4",
		"X-Deck-Member": "bob", "Anthropic-Version": "2023-06-01"}

	st, _ := k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", msg("claude-x", ""), hdrs)
	req, _ := k.anth.last()
	c.ok("P1 запрос Анны проходит", st == 200, st)
	c.ok("P2 провайдер получил НАСТОЯЩИЙ ключ Анны, а не токен пространства", req.Header.Get("x-api-key") == "sk-ant-ANNA-0123456789", req.Header.Get("x-api-key"))
	c.ok("P3 наружу не ушли Authorization/Cookie/XFF/X-Deck-*", req.Header.Get("Authorization") == "" && req.Header.Get("Cookie") == "" &&
		req.Header.Get("X-Forwarded-For") == "" && req.Header.Get("X-Deck-Member") == "" && req.Header.Get("Anthropic-Version") == "2023-06-01", req.Header)
	want := (1000*3.0 + 500*15.0) / 1e6
	c.ok("P4 расход посчитан по usage провайдера", abs(k.srv.Ledger.Spent("user:anna")-want) < 1e-9, k.srv.Ledger.Spent("user:anna"))

	before := k.srv.Ledger.Spent("user:anna")
	st, body := k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", msg("claude-x", `,"stream":true`), nil)
	c.ok("P5 поток Anthropic: usage из message_start + message_delta", st == 200 && strings.Contains(body, "message_delta") &&
		abs(k.srv.Ledger.Spent("user:anna")-before-want) < 1e-9, k.srv.Ledger.Spent("user:anna")-before)

	st, _ = k.do("POST", "/llm/sakana/v1/chat/completions", "tok-anna", msg("fugu-max-v1.0", `,"stream":true`), nil)
	_, sb := k.sak.last()
	c.ok("P6 поток Sakana: keyguard сам включил include_usage и посчитал расход", st == 200 && strings.Contains(string(sb), `"include_usage":true`) &&
		abs(k.srv.Ledger.Spent("user:anna")-before-want-(2000*2.0+1000*6.0)/1e6) < 1e-9)

	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "", msg("claude-x", ""), nil)
	c.ok("P7 без токена — 401", st == 401, st)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "forged-token", msg("claude-x", ""), nil)
	c.ok("P8 поддельный токен — 401", st == 401, st)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-random", msg("claude-x", ""), nil)
	c.ok("P9 не-пространство (space-operator) — 403", st == 403, st)

	n0 := k.anth.count() + k.sak.count()
	for _, p := range []string{"/llm/anthropic/v1/models", "/llm/anthropic/v1/messages?beta=x", "/llm/anthropic%2Fv1%2Fmessages",
		"/llm/anthropic/v1/messages/../../sakana/v1/chat/completions", "/llm/anthropic/v1//messages", "/llm/../v1/keys", "/llm/evil/v1/messages"} {
		st, _ = k.do("POST", p, "tok-anna", msg("claude-x", ""), nil)
		c.ok("P10 путь "+p+" не проксируется", st != 200, st)
	}
	c.ok("P11 ни один из этих путей не дошёл до провайдера", k.anth.count()+k.sak.count() == n0)

	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", msg("claude-x", ""), map[string]string{"Host": strings.TrimPrefix(k.ts.URL, "http://")})
	c.ok("P12 SSRF: заголовок Host не меняет адрес провайдера", k.evil.count() == 0)

	smug := []byte(`{"model":"claude-x","max_tokens":10,"model":"claude-opus-expensive","messages":[]}`)
	st, body = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", smug, nil)
	c.ok("P13 дубликат model (подмена модели) отклонён", st == 400 && strings.Contains(body, "дубликат"), st, body)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", msg("claude-opus-unpriced", ""), nil)
	c.ok("P14 модель без цены отклонена", st == 400, st)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", []byte(`{"model":"claude-x","messages":[]}`), nil)
	c.ok("P15 без max_tokens отклонено (расход не ограничить)", st == 400, st)

	st, body = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", msg("echo-key", ""), nil)
	c.ok("P16 ключ в ответе провайдера вычищен", !strings.Contains(body, "sk-ant-ANNA") && strings.Contains(body, "[redacted]"), body)

	big := bytes.Repeat([]byte("x"), 2<<20)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", big, nil)
	c.ok("P17 тело больше лимита отклонено", st == 413, st)

	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-bob", msg("claude-x", ""), map[string]string{"X-Deck-Chat": "c-42", "X-Deck-Member": "anna"})
	req, _ = k.anth.last()
	c.ok("P18 личное пространство Боба платит своим ключом (X-Deck-* не влияют)", st == 200 && req.Header.Get("x-api-key") == "sk-ant-BOB-0123456789")
	t.Logf("прокси: %d/%d", c.n, c.n+c.f)
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// ---------------- лимиты ----------------

func TestAttack_Limits(t *testing.T) {
	k := newRig(t)
	k.seed()
	c := &check{t: t}
	body := []byte(`{"model":"claude-x","max_tokens":1000,"messages":[]}`)
	reserve := (float64(len(body))*3 + 1000*15) / 1e6
	k.srv.Ledger.SetLimit("user:anna", reserve*10.5) // ровно 10 одновременных резервов помещаются

	k.slow = 300 * time.Millisecond
	var wg sync.WaitGroup
	var okN, denied int64
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, _ := k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", body, nil)
			if st == 200 {
				atomic.AddInt64(&okN, 1)
			} else if st == 402 {
				atomic.AddInt64(&denied, 1)
			}
		}()
	}
	wg.Wait()
	k.slow = 0
	spent := k.srv.Ledger.Spent("user:anna")
	c.ok("L1 40 параллельных запросов не превышают лимит (резервирование)", spent <= reserve*10.5+1e-9 && denied > 0, fmt.Sprintf("ok=%d denied=%d spent=%.4f limit=%.4f", okN, denied, spent, reserve*10.5))

	k2 := newRig(t)
	k2.seed()
	nb := []byte(`{"model":"no-usage","max_tokens":1000,"messages":[]}`)
	k2.do("POST", "/llm/anthropic/v1/messages", "tok-anna", nb, nil)
	full := (float64(len(nb))*3 + 1000*15) / 1e6
	c.ok("L2 провайдер не сообщил usage → списан весь резерв (fail-safe)", abs(k2.srv.Ledger.Spent("user:anna")-full) < 1e-9, k2.srv.Ledger.Spent("user:anna"))

	// ошибка провайдера без usage — 0; в журнале — реально списанное
	k4 := newRig(t)
	k4.seed()
	k4.srv.Store.Put(nil, "anna", "anthropic", "sk-ant-REVOKED-000000") // ключ отозван у провайдера → 401
	k4.do("POST", "/llm/anthropic/v1/messages", "tok-anna", []byte(`{"model":"claude-x","max_tokens":1000,"messages":[]}`), nil)
	c.ok("L5 провайдер отклонил запрос (401, без usage) — ничего не списано", k4.srv.Ledger.Spent("user:anna") == 0, k4.srv.Ledger.Spent("user:anna"))
	k4.do("POST", "/llm/anthropic/v1/messages", "tok-anna", []byte(`{"model":"claude-x","max_tokens":1000,"stream":true,"messages":[]}`), nil)
	c.ok("L5b то же для ПОТОКОВОГО запроса (SDK Anthropic всегда поток) — ничего не списано", k4.srv.Ledger.Spent("user:anna") == 0, k4.srv.Ledger.Spent("user:anna"))
	k2.logs.Reset()
	k2.do("POST", "/llm/anthropic/v1/messages", "tok-anna", nb, nil)
	c.ok("L6 журнал пишет фактически списанное (весь резерв при отсутствии usage)", strings.Contains(k2.logs.String(), fmt.Sprintf("charged_usd=%.6f", full)), k2.logs.String())

	// провайдер насчитал гораздо больше оценки (скрытые токены оркестрации): учёт пишет факт, лимит закрывается
	k3 := newRig(t)
	k3.seed()
	k3.srv.Ledger.SetLimit("user:anna", 0.012)
	sb := []byte(`{"model":"fugu-max-v1.0","max_tokens":1000,"messages":[]}`)
	st1, _ := k3.do("POST", "/llm/sakana/v1/chat/completions", "tok-anna", sb, nil)
	sp := k3.srv.Ledger.Spent("user:anna")
	c.ok("L3 скрытые токены: записан ФАКТ провайдера ($0.01), а не заниженный резерв", st1 == 200 && abs(sp-0.01) < 1e-9, fmt.Sprintf("%.6f", sp))
	st2, _ := k3.do("POST", "/llm/sakana/v1/chat/completions", "tok-anna", sb, nil)
	c.ok("L4 после этого лимит закрыт: следующий запрос отклонён", st2 == 402, st2)
	in, out, kn := usageOf("anthropic", []byte(`{"type":"message_start","message":{"usage":{"input_tokens":900,"output_tokens":1,"cache_read_input_tokens":300,"cache_creation_input_tokens":100}}}`))
	c.ok("L7 кэш промптов Anthropic учтён по верхней ставке записи: 900 + 100×2 + 300×0,1 = 1130", kn && in == 1130 && out == 1, in, out)
	t.Logf("лимиты: %d/%d", c.n, c.n+c.f)
}

// ---------------- разрешения спонсоров ----------------

func TestAttack_Grants(t *testing.T) {
	k := newRig(t)
	k.seed()
	c := &check{t: t}
	const until = "2026-10-08" // действует до конца этих суток (UTC)
	untilEnd := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	grant := func(p *phone, mut func(m map[string]any)) (int, string) {
		f := map[string]any{"type": "grant", "space": "t-shop", "chat": "c-42", "provider": "sakana", "model": "fugu-max-v1.0",
			"limit_usd": json.Number("20"), "limit_tokens": nil, "per_member_usd_day": json.Number("5"),
			"until": until, "key_until": until, "members": []any{"anna", "bob"}, "proposal": "p-1"}
		if mut != nil {
			mut(f)
		}
		return k.do("POST", "/v1/grants", "tok-cp", j(p.sign(t, k, f, nil)), nil)
	}
	revoke := func(p *phone, proposal string) int {
		st, _ := k.do("POST", "/v1/grants/revoke", "tok-cp",
			j(p.sign(t, k, map[string]any{"type": "grant_revoke", "space": "t-shop", "chat": "c-42", "proposal": proposal}, nil)), nil)
		return st
	}
	team := func(tok, chat, member, model string) int {
		st, _ := k.do("POST", "/llm/sakana/v1/chat/completions", tok,
			[]byte(fmt.Sprintf(`{"model":%q,"max_tokens":1000,"messages":[]}`, model)), map[string]string{"X-Deck-Chat": chat, "X-Deck-Member": member})
		return st
	}
	st, _ := grant(k.bob, func(m map[string]any) { m["limit_tokens"] = json.Number("100000") })
	c.ok("G1 лимит в токенах (не соблюдается учётом) — отклонён, а не молча проигнорирован", st == 400, st)
	st, _ = grant(k.bob, func(m map[string]any) { m["limit_usd"] = json.Number("0") })
	c.ok("G2 разрешение без лимита отклонено (схема: сумма больше нуля)", st == 403, st)
	st, _ = grant(k.bob, func(m map[string]any) { m["until"] = "2028-10-01" })
	c.ok("G3 срок больше года отклонён", st == 400, st)
	st, _ = grant(k.bob, func(m map[string]any) { m["limit_usd"] = json.Number("20.555") })
	st2, _ := grant(k.bob, func(m map[string]any) { m["limit_usd"] = json.Number("2e1") })
	st3, _ := grant(k.bob, func(m map[string]any) { m["limit_usd"] = json.Number("20.50") })
	c.ok("G4 числа не в каноничной форме (3 знака, экспонента, хвостовой ноль) отклонены", st == 403 && st2 == 403 && st3 == 403, st, st2, st3)
	st, _ = grant(k.mallory, nil)
	c.ok("G5 спонсор без ключа провайдера — 409", st == 409, st)
	st, body := grant(k.bob, nil)
	var gr map[string]string
	json.Unmarshal([]byte(body), &gr)
	gid := gr["grant_id"]
	g0, _ := k.srv.Grants.Get(gid)
	c.ok("G6 Боб создаёт разрешение; спонсор — подписавший, срок — до конца суток", st == 200 && g0 != nil && g0.Sponsor == "bob" && g0.Until.Equal(untilEnd), st, body)
	c.ok("G7 до утверждения (голосования) ключ не выдаётся", team("tok-shop", "c-42", "anna", "fugu-max-v1.0") == 403)
	st, _ = k.do("POST", "/v1/grants/activate", "tok-other", j(map[string]string{"grant_id": gid}), nil)
	c.ok("G8 другое общее пространство не может активировать чужое разрешение", st == 403, st)
	st, _ = k.do("POST", "/v1/grants/activate", "tok-anna", j(map[string]string{"grant_id": gid}), nil)
	c.ok("G9 личное пространство не может активировать", st == 403, st)
	st, actBody := k.do("POST", "/v1/grants/activate", "tok-shop", j(map[string]string{"grant_id": gid}), nil)
	var act struct {
		Grant struct {
			Chat, Proposal, Provider, Model, Sponsor string
			LimitUSD                                 float64 `json:"limit_usd"`
			Members                                  []string
			Active                                   bool
		}
	}
	json.Unmarshal([]byte(actBody), &act)
	c.ok("G10 своё пространство активирует и получает условия, подписанные спонсором", st == 200 && act.Grant.Sponsor == "bob" &&
		act.Grant.Chat == "c-42" && act.Grant.Model == "fugu-max-v1.0" && act.Grant.LimitUSD == 20 && act.Grant.Active && len(act.Grant.Members) > 0, st, actBody)
	st, _ = k.do("POST", "/v1/grants/deactivate", "tok-other", j(map[string]string{"grant_id": gid}), nil)
	c.ok("G10a чужое пространство не может снять разрешение", st == 403, st)
	st, _ = k.do("POST", "/v1/grants/deactivate", "tok-shop", j(map[string]string{"grant_id": gid}), nil)
	c.ok("G10b своё пространство снимает разрешение (модель сменили) — ключ спонсора не выдаётся", st == 200 && team("tok-shop", "c-42", "anna", "fugu-max-v1.0") == 403, st)
	st, _ = k.do("POST", "/v1/grants/activate", "tok-shop", j(map[string]string{"grant_id": gid}), nil)
	c.ok("G10c и включает снова, пока спонсор его не отозвал", st == 200, st)
	st = team("tok-shop", "c-42", "anna", "fugu-max-v1.0")
	r, _ := k.sak.last()
	c.ok("G11 Анна в чате c-42 использует ключ спонсора Боба", st == 200 && r.Header.Get("Authorization") == "Bearer sk-sak-BOB-0123456789", st)
	c.ok("G12 Мэллори (не в списке) — отклонено", team("tok-shop", "c-42", "mallory", "fugu-max-v1.0") == 403)
	c.ok("G13 другой чат — отклонено", team("tok-shop", "c-43", "anna", "fugu-max-v1.0") == 403)
	c.ok("G14 другая (дорогая) модель — отклонено", team("tok-shop", "c-42", "anna", "fugu-ultra-v2.0") == 403)
	c.ok("G15 другое пространство с тем же чатом — отклонено", team("tok-other", "c-42", "anna", "fugu-max-v1.0") == 403)
	n := 0
	for team("tok-shop", "c-42", "anna", "fugu-max-v1.0") == 200 {
		n++
		if n > 1000 {
			break
		}
	}
	day := k.now().UTC().Format("2006-01-02")
	ann := k.srv.Ledger.Spent("grant:" + gid + ":anna:" + day)
	c.ok("G16 дневной лимит участника ($5) соблюдён", ann <= 5+1e-9 && ann > 4, fmt.Sprintf("%.4f", ann))
	c.ok("G17 Боб при этом может работать", team("tok-shop", "c-42", "bob", "fugu-max-v1.0") == 200)
	k.clock = k.clock.Add(24 * time.Hour) // новый день — новый дневной лимит, общий $20 продолжает считаться
	for i := 0; i < 2000 && team("tok-shop", "c-42", "anna", "fugu-max-v1.0") == 200; i++ {
		if i%50 == 49 {
			k.clock = k.clock.Add(24 * time.Hour)
		}
		if k.clock.After(untilEnd) {
			break
		}
	}
	total := k.srv.Ledger.Spent("grant:" + gid)
	c.ok("G18 общий лимит разрешения ($20) не превышен", total <= 20+1e-9, fmt.Sprintf("%.4f", total))
	k.clock = untilEnd.Add(-time.Minute)
	k.srv.Ledger.SetLimit("grant:"+gid, 1000)
	c.ok("G19a в последний день срока ключ ещё выдаётся", team("tok-shop", "c-42", "bob", "fugu-max-v1.0") == 200)
	k.clock = untilEnd.Add(time.Second)
	c.ok("G19 после срока ключ спонсора не выдаётся", team("tok-shop", "c-42", "bob", "fugu-max-v1.0") == 403)

	k.clock = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	k.srv.Ledger.SetLimit("grant:"+gid, 1000)
	st, body = grant(k.bob, func(m map[string]any) { m["proposal"] = "p-2"; m["limit_usd"] = json.Number("12.5") })
	json.Unmarshal([]byte(body), &gr)
	g2 := gr["grant_id"]
	gg, _ := k.srv.Grants.Get(g2)
	c.ok("G19b сумма с копейками ($12.5), как её шлёт приложение, принимается", st == 200 && gg != nil && gg.LimitUSD == 12.5, st, body)
	k.do("POST", "/v1/grants/activate", "tok-shop", j(map[string]string{"grant_id": g2}), nil)
	c.ok("G20 участник не может отозвать чужое разрешение", revoke(k.anna, "p-2") == 403)
	c.ok("G21a пока действуют разрешения — запрос проходит", team("tok-shop", "c-42", "bob", "fugu-max-v1.0") == 200)
	st, st2 = revoke(k.bob, "p-2"), revoke(k.bob, "p-1")
	c.ok("G21 спонсор отзывает оба (по чату и предложению) — ключ сразу перестаёт выдаваться", st == 200 && st2 == 200 && team("tok-shop", "c-42", "bob", "fugu-max-v1.0") == 403, st, st2)
	c.ok("G22 повторный отзыв уже отозванного — 403", revoke(k.bob, "p-1") == 403)
	t.Logf("разрешения: %d/%d", c.n, c.n+c.f)
}

// ---------------- журналы ----------------

func TestAttack_NoSecretsInLogs(t *testing.T) {
	k := newRig(t)
	c := &check{t: t}
	r, _ := k.sealedKeyPut(k.anna, "anthropic", "sk-ant-ANNA-0123456789", nil)
	k.do("POST", "/v1/keys", "tok-cp", j(r), nil)
	k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", []byte(`{"model":"claude-x","max_tokens":10,"messages":[]}`), nil)
	k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", []byte(`{"model":"echo-key","max_tokens":10,"messages":[]}`), nil)
	logs := k.logs.String()
	c.ok("N1 в журнале нет ключа API", !strings.Contains(logs, "ANNA-0123456789"), logs)
	c.ok("N2 в журнале нет токена пространства", !strings.Contains(logs, "tok-anna"))
	c.ok("N3 журнал содержит события (не пустой)", strings.Contains(logs, "event=key.put") && strings.Contains(logs, "event=llm"))
}

// ---------------- учёт: обрыв потока, кэш, инструменты, id разрешений ----------------

func TestAttack_Accounting(t *testing.T) {
	k := newRig(t)
	k.seed()
	c := &check{t: t}

	// поток оборван до message_stop: списывается не меньше резерва, а не «вход + 1 токен»
	cut := []byte(`{"model":"claude-x","max_tokens":1000,"messages":[],"stream":true,"metadata":{"user_id":"cut"}}`)
	reserve := (float64(len(cut))*3 + 1000*15) / 1e6
	k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", cut, nil)
	sp := k.srv.Ledger.Spent("user:anna")
	c.ok("A1 оборванный поток: списан резерв, а не неполный usage", abs(sp-reserve) < 1e-9, fmt.Sprintf("%.6f want %.6f", sp, reserve))

	// кэш-токены Anthropic входят во вход: запись ×2, чтение ×0,1
	in, out, ok := usageOf("anthropic", []byte(`{"usage":{"input_tokens":100,"output_tokens":7,"cache_creation_input_tokens":1000,"cache_read_input_tokens":5000}}`))
	c.ok("A2 кэш-токены учтены во входе", ok && in == 100+2000+500 && out == 7, in, out)

	// серверные инструменты и неизвестные поля не проходят; клиентские инструменты — проходят
	n0 := k.anth.count()
	body := func(extra string) []byte {
		return []byte(`{"model":"claude-x","max_tokens":10,"messages":[]` + extra + `}`)
	}
	st, _ := k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", body(`,"tools":[{"type":"web_search_20250305","name":"web_search"}]`), nil)
	c.ok("A3 серверный инструмент (web_search) отклонён", st == 400, st)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", body(`,"service_tier":"priority"`), nil)
	c.ok("A4 неизвестное поле тела отклонено", st == 400, st)
	c.ok("A5 отклонённые запросы не дошли до провайдера", k.anth.count() == n0)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", body(`,"tools":[{"name":"run","input_schema":{"type":"object"}},{"type":"bash_20250124","name":"bash"}]`), nil)
	c.ok("A6 клиентские инструменты проходят", st == 200, st)
	k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", body(""), map[string]string{"Anthropic-Beta": "context-1m-2025-08-07"})
	up, _ := k.anth.last()
	c.ok("A7 Anthropic-Beta наружу не уходит", up.Header.Get("Anthropic-Beta") == "")

	// id разрешения: чужое устройство с тем же nonce не затирает разрешение; повтор своего — отказ
	mk := func(p *phone, limit string) SignedAction {
		return p.sign(t, k, map[string]any{"type": "grant", "space": "t-shop", "chat": "c-1", "provider": "sakana", "model": "fugu-max-v1.0",
			"limit_usd": json.Number(limit), "limit_tokens": nil, "per_member_usd_day": nil, "until": "2026-10-02", "key_until": "2026-10-02",
			"members": []any{"anna"}, "proposal": "p-9", "nonce": "same-nonce-0000000000"}, nil)
	}
	var g1, g2 map[string]string
	st, b1 := k.do("POST", "/v1/grants", "tok-cp", j(mk(k.bob, "20")), nil)
	json.Unmarshal([]byte(b1), &g1)
	st2, b2 := k.do("POST", "/v1/grants", "tok-cp", j(mk(k.anna, "999")), nil)
	json.Unmarshal([]byte(b2), &g2)
	gb, _ := k.srv.Grants.Get(g1["grant_id"])
	c.ok("A8 тот же nonce с другого устройства — другое разрешение, чужое не затёрто",
		st == 200 && st2 == 200 && g1["grant_id"] != g2["grant_id"] && gb != nil && gb.Sponsor == "bob" && gb.LimitUSD == 20, st, st2)
	c.ok("A9 Grants.Put не перезаписывает существующее", func() bool { ok, _ := k.srv.Grants.Put(&Grant{ID: g1["grant_id"], Sponsor: "mallory"}); return !ok }())

	// журнал: хеши вместо id пользователей
	logs := k.logs.String()
	c.ok("A10 в журнале нет id пользователей открытым текстом", !strings.Contains(logs, "payer=anna") && !strings.Contains(logs, "deck-u-anna") &&
		!strings.Contains(logs, "sponsor=bob") && strings.Contains(logs, "payer="+uid("anna")), logs)

	st, _ = k.do("GET", "/v1/grants/activate", "tok-shop", nil, nil)
	c.ok("A11 activate — только POST", st == 405, st)
	t.Logf("учёт: %d/%d", c.n, c.n+c.f)
}

// ---------------- проверка подписей для исполнителей (space-operator, ssh-gateway) ----------------

func TestAttack_VerifyAction(t *testing.T) {
	k := newRig(t)
	c := &check{t: t}
	verify := func(tok string, sa SignedAction) (int, map[string]any) {
		st, body := k.do("POST", "/v1/actions/verify", tok, j(sa), nil)
		var m map[string]any
		json.Unmarshal([]byte(body), &m)
		return st, m
	}
	del := k.anna.sign(t, k, map[string]any{"type": "space_delete", "space": "u-anna"}, nil)
	st, m := verify("tok-random", del)
	act, _ := m["action"].(map[string]any)
	c.ok("V1 space-operator проверяет подписанное удаление: получает действие и подписавшего",
		st == 200 && m["user"] == "anna" && act["type"] == "space_delete" && act["space"] == "u-anna", st, m)
	st, _ = verify("tok-random", del)
	c.ok("V2 ту же подпись нельзя предъявить второй раз", st == 403, st)
	st, _ = verify("tok-cp", k.anna.sign(t, k, map[string]any{"type": "space_delete", "space": "u-anna"}, nil))
	c.ok("V3 control-plane не исполнитель — проверять (и сжигать nonce) не может", st == 403, st)
	st, _ = verify("tok-anna", k.anna.sign(t, k, map[string]any{"type": "space_delete", "space": "u-anna"}, nil))
	c.ok("V4 пространство не может проверять подписи", st == 403, st)
	st, _ = verify("tok-random", k.anna.sign(t, k, map[string]any{"type": "ssh_write", "agent": "duty", "server": "prod-1", "command": "reboot"}, nil))
	c.ok("V5 space-operator не принимает действия ssh-gateway", st == 403, st)
	st, m = verify("tok-ssh", k.anna.sign(t, k, map[string]any{"type": "ssh_write", "agent": "duty", "server": "prod-1", "command": "systemctl restart app"}, nil))
	act, _ = m["action"].(map[string]any)
	c.ok("V6 ssh-gateway проверяет подписанную команду", st == 200 && act["command"] == "systemctl restart app", st)
	st, _ = verify("tok-random", k.mallory.sign(t, k, map[string]any{"type": "account_delete", "user": "anna"}, nil))
	c.ok("V7 удалить чужой аккаунт своей подписью нельзя", st == 403, st)
	st, _ = verify("tok-random", k.anna.sign(t, k, map[string]any{"type": "space_delete", "space": "u-anna"}, k.anna.session))
	c.ok("V8 подпись ключом сессии — отказ", st == 403, st)
	st, _ = verify("tok-random", SignedAction{JWS: jwsOf(payloadOf(del.JWS), k.anna.dev.ID, k.mallory.confirm)})
	c.ok("V9 control-plane подделывает удаление чужого пространства — отказ", st == 403, st)
	// личное пространство проверяет разрешения владельца на действия агента — и только их
	ap := func(p *phone, space string) SignedAction {
		return p.sign(t, k, map[string]any{"type": "tool_approve", "space": space, "approval": "a1b2c3", "tool": "github_create_file",
			"args_sha256": strings.Repeat("a", 43)}, nil)
	}
	st, m = verify("tok-anna", ap(k.anna, "u-anna"))
	act, _ = m["action"].(map[string]any)
	c.ok("V10 пространство Анны проверяет её разрешение агенту", st == 200 && m["user"] == "anna" && act["tool"] == "github_create_file", st, m)
	once := ap(k.anna, "u-anna")
	verify("tok-anna", once)
	st, _ = verify("tok-anna", once)
	c.ok("V11 то же разрешение второй раз не принимается", st == 403, st)
	st, _ = verify("tok-anna", ap(k.mallory, "u-anna"))
	c.ok("V12 разрешение, подписанное не владельцем пространства, — отказ", st == 403, st)
	st, _ = verify("tok-bob", ap(k.anna, "u-anna"))
	c.ok("V13 разрешение Анны для её пространства в чужом пространстве не действует", st == 403, st)
	st, _ = verify("tok-anna", ap(k.anna, "u-bob"))
	c.ok("V14 разрешение Анны, подписанное для другого пространства, — отказ", st == 403, st)
	st, m = verify("tok-shop", ap(k.anna, "t-shop"))
	c.ok("V15 общее пространство проверяет разрешение участника и узнаёт, кто подписал", st == 200 && m["user"] == "anna", st, m)
	st, _ = verify("tok-other", ap(k.anna, "t-shop"))
	c.ok("V15a разрешение для одного общего пространства в другом не действует", st == 403, st)
	st, _ = verify("tok-shop", ap(k.anna, "u-anna"))
	c.ok("V15b разрешение для личного пространства в общем не действует", st == 403, st)
	st, _ = verify("tok-shop", k.anna.sign(t, k, map[string]any{"type": "space_delete", "space": "t-shop"}, nil))
	c.ok("V15c общее пространство не может проверять (и сжигать) подписи других типов", st == 403, st)
	st, _ = verify("tok-anna", k.anna.sign(t, k, map[string]any{"type": "ssh_write", "agent": "duty", "server": "prod-1", "command": "reboot"}, nil))
	c.ok("V16 пространство не может проверять (и сжигать) подписи других типов", st == 403, st)
	t.Logf("проверка подписей: %d/%d", c.n, c.n+c.f)
}
