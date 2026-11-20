package controlplane

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Стенд входа на api: «Keycloak» (ключ RSA и JWKS), «CA устройств» и телефон с ключом сессии.
type authStand struct {
	*stand
	kc     *rsa.PrivateKey
	device *ecdsa.PrivateKey
	cert   string // заголовок Traefik: DER в base64
	jwks   *httptest.Server
}

func ecJWK(k *ecdsa.PublicKey) map[string]string {
	x, y := make([]byte, 32), make([]byte, 32)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	return map[string]string{"kty": "EC", "crv": "P-256", "x": b64.EncodeToString(x), "y": b64.EncodeToString(y)}
}

func signES(k *ecdsa.PrivateKey, header, claims map[string]any) string {
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	in := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	d := sha256.Sum256([]byte(in))
	r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + b64.EncodeToString(sig)
}

func signRS(k *rsa.PrivateKey, kid string, claims map[string]any) string {
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	cb, _ := json.Marshal(claims)
	in := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	d := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	return in + "." + b64.EncodeToString(sig)
}

func certFor(t *testing.T, pub *ecdsa.PublicKey, cn string, notAfter time.Time) (der []byte) {
	t.Helper()
	ca, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: notAfter.Add(-30 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, ca)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newAuthStand(t *testing.T) *authStand {
	t.Helper()
	a := &authStand{stand: newStand()}
	a.kc, _ = rsa.GenerateKey(rand.Reader, 2048)
	a.device, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a.cert = base64.StdEncoding.EncodeToString(certFor(t, &a.device.PublicKey, "d-device1", a.now.Add(24*time.Hour)))
	a.jwks = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64.EncodeToString(a.kc.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(a.kc.E)).Bytes())}}})
	}))
	t.Cleanup(a.jwks.Close)
	a.s.Keys = &KeySet{URL: a.jwks.URL, HTTP: a.jwks.Client()}
	return a
}

func (a *authStand) jkt(k *ecdsa.PrivateKey) string { return ecThumbprint(k.X, k.Y) }

func (a *authStand) token(over map[string]any) string {
	c := map[string]any{"iss": a.s.Cfg.Issuer, "azp": "deck-app", "exp": a.now.Add(5 * time.Minute).Unix(),
		"preferred_username": "anna", "cnf": map[string]any{"jkt": a.jkt(a.device)}}
	for k, v := range over {
		c[k] = v
	}
	return signRS(a.kc, "k1", c)
}

func (a *authStand) proof(k *ecdsa.PrivateKey, method, htu, token string, over map[string]any) string {
	ath := sha256.Sum256([]byte(token))
	c := map[string]any{"jti": "jti-" + b64.EncodeToString(randBytes(9)), "htm": method, "htu": htu, "iat": a.now.Unix(),
		"ath": b64.EncodeToString(ath[:])}
	for key, v := range over {
		c[key] = v
	}
	return signES(k, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": ecJWK(&k.PublicKey)}, c)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// req — запрос к api с правильными по умолчанию сертификатом, токеном и доказательством; edit портит что нужно.
func (a *authStand) req(method, path, body string, edit func(r *http.Request)) *httptest.ResponseRecorder {
	tok := a.token(nil)
	r := httptest.NewRequest(method, "https://api.deck.test"+path, strings.NewReader(body))
	r.Header.Set(certHeader, a.cert)
	r.Header.Set("Authorization", "DPoP "+tok)
	htu, _, _ := strings.Cut("https://api.deck.test"+path, "?") // приложение подписывает адрес без параметров запроса
	r.Header.Set("DPoP", a.proof(a.device, method, htu, tok, nil))
	if edit != nil {
		edit(r)
	}
	w := httptest.NewRecorder()
	a.s.PublicHandler().ServeHTTP(w, r)
	return w
}

func TestAPIAuth(t *testing.T) {
	a := newAuthStand(t)
	w := a.req("GET", "/v1/me", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"user":"anna"`) || !strings.Contains(w.Body.String(), `"device_id":"d-device1"`) {
		t.Fatalf("честный запрос: %d %s", w.Code, w.Body)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	evilKC, _ := rsa.GenerateKey(rand.Reader, 2048)
	set := func(tok string, k *ecdsa.PrivateKey, over map[string]any) func(*http.Request) {
		return func(r *http.Request) {
			r.Header.Set("Authorization", "DPoP "+tok)
			r.Header.Set("DPoP", a.proof(k, "GET", "https://api.deck.test/v1/me", tok, over))
		}
	}
	good := a.token(nil)
	attacks := map[string]func(*http.Request){
		"без сертификата":          func(r *http.Request) { r.Header.Del(certHeader) },
		"мусор вместо сертификата": func(r *http.Request) { r.Header.Set(certHeader, "AAAA") },
		"без токена":               func(r *http.Request) { r.Header.Del("Authorization") },
		"Bearer вместо DPoP":       func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+good) },
		"без DPoP":                 func(r *http.Request) { r.Header.Del("DPoP") },
		"токен чужого Keycloak":    set(signRS(evilKC, "k1", map[string]any{"iss": a.s.Cfg.Issuer, "azp": "deck-app", "exp": a.now.Add(time.Minute).Unix(), "preferred_username": "anna", "cnf": map[string]any{"jkt": a.jkt(a.device)}}), a.device, nil),
		"чужой издатель":           set(a.token(map[string]any{"iss": "https://evil.example/realms/deck"}), a.device, nil),
		"токен другого клиента":    set(a.token(map[string]any{"azp": "admin-cli"}), a.device, nil),
		"истёкший токен":           set(a.token(map[string]any{"exp": a.now.Add(-time.Second).Unix()}), a.device, nil),
		"токен без привязки":       set(a.token(map[string]any{"cnf": nil}), a.device, nil),
		"токен привязан к чужому ключу, DPoP тем же чужим ключом": set(a.token(map[string]any{"cnf": map[string]any{"jkt": a.jkt(other)}}), other, nil),
		"DPoP чужим ключом":         set(good, other, nil),
		"DPoP на другой метод":      set(good, a.device, map[string]any{"htm": "POST"}),
		"DPoP на другой адрес":      set(good, a.device, map[string]any{"htu": "https://api.deck.test/v1/keys"}),
		"DPoP на другой хост":       set(good, a.device, map[string]any{"htu": "https://evil.example/v1/me"}),
		"DPoP для другого токена":   set(good, a.device, map[string]any{"ath": "AAAA"}),
		"DPoP из прошлого":          set(good, a.device, map[string]any{"iat": a.now.Add(-2 * time.Minute).Unix()}),
		"DPoP из будущего":          set(good, a.device, map[string]any{"iat": a.now.Add(2 * time.Minute).Unix()}),
		"DPoP без jti":              set(good, a.device, map[string]any{"jti": ""}),
		"недопустимое имя в токене": set(a.token(map[string]any{"preferred_username": "../admin"}), a.device, nil),
		"запрос пришёл на join":     func(r *http.Request) { r.Host = "join.deck.test" },
	}
	for name, edit := range attacks {
		if w := a.req("GET", "/v1/me", "", edit); w.Code == 200 {
			t.Errorf("%s: запрос принят", name)
		}
	}

	// alg=none и подмена алгоритма
	hb, _ := json.Marshal(map[string]any{"alg": "none", "kid": "k1"})
	cb, _ := json.Marshal(map[string]any{"iss": a.s.Cfg.Issuer, "azp": "deck-app", "exp": a.now.Add(time.Minute).Unix(),
		"preferred_username": "anna", "cnf": map[string]any{"jkt": a.jkt(a.device)}})
	none := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb) + "."
	if w := a.req("GET", "/v1/me", "", set(none, a.device, nil)); w.Code == 200 {
		t.Error("alg=none принят")
	}

	// повтор того же доказательства
	tok := a.token(nil)
	proof := a.proof(a.device, "GET", "https://api.deck.test/v1/me", tok, nil)
	same := func(r *http.Request) { r.Header.Set("Authorization", "DPoP "+tok); r.Header.Set("DPoP", proof) }
	if w := a.req("GET", "/v1/me", "", same); w.Code != 200 {
		t.Fatalf("первое предъявление: %d %s", w.Code, w.Body)
	}
	if w := a.req("GET", "/v1/me", "", same); w.Code != 401 {
		t.Errorf("повтор DPoP принят: %d", w.Code)
	}

	// сертификат истёк
	a.cert = base64.StdEncoding.EncodeToString(certFor(t, &a.device.PublicKey, "d-device1", a.now.Add(-time.Hour)))
	if w := a.req("GET", "/v1/me", "", nil); w.Code != 401 {
		t.Errorf("истёкший сертификат принят: %d", w.Code)
	}
	// сертификат на другой ключ при честном токене и DPoP
	a.cert = base64.StdEncoding.EncodeToString(certFor(t, &other.PublicKey, "d-device1", a.now.Add(time.Hour)))
	if w := a.req("GET", "/v1/me", "", nil); w.Code != 401 {
		t.Errorf("сертификат на чужой ключ принят: %d", w.Code)
	}
}

// Traefik может передать сертификат по-разному: голый base64, с экранированием для URL, в PEM, цепочкой.
func TestDeviceCertFormats(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := certFor(t, &k.PublicKey, "d-x", time.Now().Add(time.Hour))
	b := base64.StdEncoding.EncodeToString(der)
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for name, h := range map[string]string{"base64": b, "url": url.QueryEscape(b), "pem": p, "pem+url": url.QueryEscape(p), "цепочка": b + "," + b} {
		c, err := deviceCert(h)
		if err != nil || c.Subject.CommonName != "d-x" {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, bad := range []string{"", "!!!", base64.StdEncoding.EncodeToString([]byte("не сертификат"))} {
		if _, err := deviceCert(bad); err == nil {
			t.Errorf("принят %q", bad)
		}
	}
}

func TestAPIKeys(t *testing.T) {
	a := newAuthStand(t)
	a.kg.resp = `{"ok":true,"masked":"sk-…abcd"}`
	body := `{"jws":"x.y.z","enc":"AA==","ct":"BB=="}`
	w := a.req("POST", "/v1/keys", body, nil)
	if w.Code != 200 || w.Body.String() != a.kg.resp || a.kg.calls[0] != "/v1/keys" || string(a.kg.bodies[0]) != body {
		t.Fatalf("ввод ключа: %d %s %v", w.Code, w.Body, a.kg.calls)
	}
	a.kg.status, a.kg.resp = 403, `{"error":"шифротекст не соответствует подписи"}`
	if w := a.req("POST", "/v1/keys", body, nil); w.Code != 403 || !strings.Contains(w.Body.String(), "шифротекст") {
		t.Fatalf("отказ keyguard не передан: %d", w.Code)
	}
	n := len(a.kg.calls)
	if w := a.req("POST", "/v1/keys", body, func(r *http.Request) { r.Header.Del("DPoP") }); w.Code != 401 {
		t.Fatalf("без DPoP: %d", w.Code)
	}
	if w := a.req("GET", "/v1/keys", "", nil); w.Code != 405 {
		t.Fatalf("GET: %d", w.Code)
	}
	if w := a.req("POST", "/v1/keys", strings.Repeat("x", 70<<10), nil); w.Code != 413 {
		t.Fatalf("большое тело: %d", w.Code)
	}
	if len(a.kg.calls) != n {
		t.Fatal("отклонённый запрос дошёл до keyguard")
	}
}

func TestAPIKeyDeleteStatusLimit(t *testing.T) {
	a := newAuthStand(t)
	a.kg.resp = `{"ok":true}`
	body := `{"jws":"x.y.z"}`
	if w := a.req("POST", "/v1/keys/delete", body, nil); w.Code != 200 || a.kg.calls[0] != "/v1/keys/delete" || string(a.kg.bodies[0]) != body {
		t.Fatalf("удаление: %d %v", w.Code, a.kg.calls)
	}
	if w := a.req("POST", "/v1/limits", body, nil); w.Code != 200 || a.kg.calls[1] != "/v1/limits" || string(a.kg.bodies[1]) != body {
		t.Fatalf("лимит: %d %v", w.Code, a.kg.calls)
	}
	a.kg.resp = `{"providers":["sakana"]}`
	if w := a.req("GET", "/v1/keys/status", "", nil); w.Code != 200 || a.kg.calls[2] != "/v1/keys/status" || !strings.Contains(string(a.kg.bodies[2]), `"user":`) {
		t.Fatalf("статус: %d %v %s", w.Code, a.kg.calls, a.kg.bodies[2])
	}
	n := len(a.kg.calls)
	if w := a.req("POST", "/v1/keys/delete", body, func(r *http.Request) { r.Header.Del("DPoP") }); w.Code != 401 || len(a.kg.calls) != n {
		t.Fatalf("без DPoP: %d", w.Code)
	}
}

func TestAppLatest(t *testing.T) {
	a := newAuthStand(t)
	a.s.Cfg.AppLatest, a.s.Cfg.AppURL = "0.5.5", "https://github.com/x/y/releases/latest"
	w := a.req("GET", "/v1/app", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"latest":"0.5.5"`) || !strings.Contains(w.Body.String(), "releases/latest") {
		t.Fatalf("версия приложения: %d %s", w.Code, w.Body)
	}
	if w := a.req("GET", "/v1/app", "", func(r *http.Request) { r.Header.Del("DPoP") }); w.Code != 401 {
		t.Fatalf("без входа: %d", w.Code)
	}
}

func TestAPIMcp(t *testing.T) {
	a := newAuthStand(t)
	a.kg.resp = `{"ok":true,"id":"docs"}`
	body := `{"jws":"x.y.z","enc":"AA==","ct":"BB=="}`
	if w := a.req("POST", "/v1/mcp", body, nil); w.Code != 200 || a.kg.calls[len(a.kg.calls)-1] != "/v1/mcp" || string(a.kg.bodies[len(a.kg.bodies)-1]) != body {
		t.Fatalf("mcp_put не передан как есть: %d %v", w.Code, a.kg.calls)
	}
	if w := a.req("POST", "/v1/mcp/delete", `{"jws":"x.y.z"}`, nil); w.Code != 200 || a.kg.calls[len(a.kg.calls)-1] != "/v1/mcp/delete" {
		t.Fatalf("mcp_delete: %d %v", w.Code, a.kg.calls)
	}
	a.kg.resp = `{"servers":[]}`
	if w := a.req("GET", "/v1/mcp/list", "", nil); w.Code != 200 || !strings.Contains(string(a.kg.bodies[len(a.kg.bodies)-1]), `"user":`) {
		t.Fatalf("список MCP: %d", w.Code)
	}
	n := len(a.kg.calls)
	if w := a.req("POST", "/v1/mcp", body, func(r *http.Request) { r.Header.Del("DPoP") }); w.Code != 401 || len(a.kg.calls) != n {
		t.Fatalf("без DPoP ушло в keyguard: %d", w.Code)
	}
}

func TestAPIEgress(t *testing.T) {
	a := newAuthStand(t)
	a.kg.resp = `{"ok":true,"domains":["docs.python.org"]}`
	if w := a.req("POST", "/v1/egress", `{"jws":"x.y.z"}`, nil); w.Code != 200 || a.kg.calls[len(a.kg.calls)-1] != "/v1/egress" || string(a.kg.bodies[len(a.kg.bodies)-1]) != `{"jws":"x.y.z"}` {
		t.Fatalf("egress_set не передан как есть: %d %v", w.Code, a.kg.calls)
	}
	a.kg.resp = `{"domains":[]}`
	if w := a.req("GET", "/v1/egress/list", "", nil); w.Code != 200 || a.kg.calls[len(a.kg.calls)-1] != "/v1/egress/list" || !strings.Contains(string(a.kg.bodies[len(a.kg.bodies)-1]), `"user":"anna"`) {
		t.Fatalf("список доменов: %d %v", w.Code, a.kg.calls)
	}
}
