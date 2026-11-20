// kgcheck — перекрёстная проверка с приложением (mobile/tests/keyguard.cross.test.ts): построчно JSON на stdin.
//
//	{"op":"canon","value":...}                       → каноничная форма keyguard
//	{"op":"verify","jwk":{"x","y"},"signed":{...},"now_ms":N,"type":"..."} → "ok" или текст ошибки
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	kg "keyguard"
)

// serve — настоящий keyguard на 127.0.0.1 для сквозного теста приложения (mobile/scripts/e2e_test.sh).
// Обработчики, проверка токенов Keycloak, DPoP, подписи действий и HPKE — боевые. Подменено окружение:
// ключи API в памяти вместо OpenBao, свой CA устройств вместо pki-device, вызывающий опознаётся по постоянному
// токену вместо TokenReview, провайдер моделей — заглушка. Эти части проверяют scripts/integration_test.sh.
// Первой строкой печатает JSON: адрес, публичный ключ HPKE, CA устройств, токен control-plane.
func serve() {
	sk, _ := ecdh.P256().GenerateKey(rand.Reader)
	prov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ca := newLocalCA()
	now := time.Now
	iss := os.Getenv("KG_ISSUER")
	srv := &kg.Server{Providers: map[string]*kg.Provider{
		"anthropic": {Name: "anthropic", BaseURL: prov.URL, Path: "/v1/messages", ProbePath: "/v1/models", AuthHeader: "x-api-key"},
		"sakana":    {Name: "sakana", BaseURL: prov.URL, Path: "/v1/chat/completions", ProbePath: "/v1/models", AuthHeader: "authorization", Style: "openai"}},
		Store: kg.NewMemStore(), Verifier: &kg.Verifier{Devices: kg.NewDevices(), Nonces: kg.NewNonces(), Now: now},
		Auth: kg.StaticAuth{"cp-token": {Namespace: "deck-system", ServiceAccount: "control-plane"}}, HPKEKey: sk,
		Upstream: http.DefaultClient, Log: log.New(os.Stderr, "kg ", 0), Now: now, MaxBody: 1 << 20,
		ControlPlane:    kg.Caller{Namespace: "deck-system", ServiceAccount: "control-plane"},
		ActionVerifiers: map[kg.Caller][]string{{Namespace: "deck-system", ServiceAccount: "control-plane"}: {"invite_create", "role_change", "pair_approve"}},
		Certs:           ca,
		Enroll: &kg.EnrollConfig{Issuer: iss, JWKSURL: os.Getenv("KG_JWKS"), ClientID: "deck-app",
			EnrollURL: os.Getenv("KG_ENROLL_URL"), StatusURL: os.Getenv("KG_ENROLL_URL") + "/status",
			Admins: []string{os.Getenv("KG_ADMIN")}, BootstrapUser: os.Getenv("KG_ADMIN"), HTTP: http.DefaultClient}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	out, _ := json.Marshal(map[string]string{
		"addr": "http://" + ln.Addr().String(), "token": "cp-token",
		"hpke_pub": base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes()),
		"ca_pem":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))})
	fmt.Println(string(out))
	log.Fatal(http.Serve(ln, srv.Handler()))
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		serve()
		return
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var in struct {
			Op     string                `json:"op"`
			Value  json.RawMessage       `json:"value"`
			JWK    struct{ X, Y string } `json:"jwk"`
			Signed kg.SignedAction       `json:"signed"`
			NowMs  int64                 `json:"now_ms"`
			Type   string                `json:"type"`
			Dev    string                `json:"device_id"`
			SkHex  string                `json:"sk_hex"`
			Req    json.RawMessage       `json:"req"`
			Enc    string                `json:"enc"`
			Ct     string                `json:"ct"`
			Aad    string                `json:"aad"`
			Issuer string                `json:"issuer"`
			JWKS   string                `json:"jwks_url"`
			EnrURL string                `json:"enroll_url"`
			Steps  []struct {
				Path string          `json:"path"`
				Body json.RawMessage `json:"body"`
			} `json:"steps"`
		}
		if err := json.Unmarshal(sc.Bytes(), &in); err != nil {
			fmt.Println("ERR", err)
			continue
		}
		switch in.Op {
		case "canon":
			m, err := kg.ParseStrict([]byte(`{"v":`+string(in.Value)+`}`), true)
			if err != nil {
				fmt.Println("ERR", err)
				continue
			}
			c := kg.Canonical(m)
			fmt.Println(string(c[5 : len(c)-1]))
		case "hpke-open": // вектор из приложения → HPKEOpen keyguard
			raw, _ := hex.DecodeString(in.SkHex)
			sk, _ := ecdh.P256().NewPrivateKey(raw)
			enc, _ := base64.StdEncoding.DecodeString(in.Enc)
			ct, _ := base64.StdEncoding.DecodeString(in.Ct)
			pt, err := kg.HPKEOpen(sk, enc, []byte(kg.HPKEInfo), []byte(in.Aad), ct)
			if err != nil {
				fmt.Println("ERR", err)
			} else {
				fmt.Println(string(pt))
			}
		case "keyput": // запрос key_put из приложения → настоящий обработчик /v1/keys
			raw, _ := hex.DecodeString(in.SkHex)
			sk, _ := ecdh.P256().NewPrivateKey(raw)
			x, _ := base64.RawURLEncoding.DecodeString(in.JWK.X)
			y, _ := base64.RawURLEncoding.DecodeString(in.JWK.Y)
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			prov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("x-api-key") == "" && r.Header.Get("Authorization") == "" {
					w.WriteHeader(401)
				}
			}))
			devs := kg.NewDevices()
			devs.Add(&kg.Device{ID: in.Dev, User: "anna", ConfirmPub: pub, SessionPub: pub})
			now := func() time.Time { return time.UnixMilli(in.NowMs) }
			store := kg.NewMemStore()
			srv := &kg.Server{Providers: map[string]*kg.Provider{
				"anthropic": {Name: "anthropic", BaseURL: prov.URL, Path: "/v1/messages", ProbePath: "/v1/models", AuthHeader: "x-api-key"},
				"kimi":      {Name: "kimi", BaseURL: prov.URL, Path: "/v1/chat/completions", ProbePath: "/v1/models", AuthHeader: "authorization"},
				"github":    kg.GitHubProvider(prov.URL)},
				Store: store, Verifier: &kg.Verifier{Devices: devs, Nonces: kg.NewNonces(), Now: now}, Ledger: kg.NewLedger(),
				Auth: kg.StaticAuth{"cp": {Namespace: "deck-system", ServiceAccount: "control-plane"}}, HPKEKey: sk,
				Upstream: http.DefaultClient, Log: log.New(io.Discard, "", 0), Now: now, MaxBody: 1 << 20,
				ControlPlane: kg.Caller{Namespace: "deck-system", ServiceAccount: "control-plane"}}
			for i := 0; i < 2; i++ { // второй раз — тот же запрос (повтор)
				rq := httptest.NewRequest("POST", "/v1/keys", bytes.NewReader(in.Req))
				rq.Header.Set("x-api-key", "cp")
				rw := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rw, rq)
				stored := ""
				for _, p := range []string{"anthropic", "github", "kimi"} {
					if k, err := store.Get(nil, "anna", p); err == nil {
						stored = p + "=" + k
					}
				}
				fmt.Printf("%d|%s|%s\n", rw.Code, stored, strings.TrimSpace(rw.Body.String()))
			}
			prov.Close()
		case "script": // сценарий на ОДНОМ keyguard: регистрация (Keycloak по-настоящему) → подтверждение → ввод ключа
			raw, _ := hex.DecodeString(in.SkHex)
			sk, _ := ecdh.P256().NewPrivateKey(raw)
			prov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			now := time.Now
			srv := &kg.Server{Providers: map[string]*kg.Provider{
				"anthropic": {Name: "anthropic", BaseURL: prov.URL, Path: "/v1/messages", ProbePath: "/v1/models", AuthHeader: "x-api-key"}},
				Store: kg.NewMemStore(), Verifier: &kg.Verifier{Devices: kg.NewDevices(), Nonces: kg.NewNonces(), Now: now},
				Auth: kg.StaticAuth{"cp": {Namespace: "deck-system", ServiceAccount: "control-plane"}}, HPKEKey: sk,
				Upstream: http.DefaultClient, Log: log.New(io.Discard, "", 0), Now: now, MaxBody: 1 << 20,
				ControlPlane: kg.Caller{Namespace: "deck-system", ServiceAccount: "control-plane"},
				Certs:        newLocalCA(),
				Enroll: &kg.EnrollConfig{Issuer: in.Issuer, JWKSURL: in.JWKS, ClientID: "deck-app", EnrollURL: in.EnrURL,
					StatusURL: strings.TrimSuffix(in.EnrURL, "/v1/enroll") + "/v1/enroll/status",
					Admins:    []string{"admin"}, BootstrapUser: "admin", HTTP: http.DefaultClient}}
			for _, st := range in.Steps {
				rq := httptest.NewRequest("POST", st.Path, bytes.NewReader(st.Body))
				rq.Header.Set("x-api-key", "cp")
				rw := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rw, rq)
				fmt.Printf("%d %s\n", rw.Code, strings.TrimSpace(rw.Body.String()))
			}
			prov.Close()
		case "verify":
			x, _ := base64.RawURLEncoding.DecodeString(in.JWK.X)
			y, _ := base64.RawURLEncoding.DecodeString(in.JWK.Y)
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			devs := kg.NewDevices()
			devs.Add(&kg.Device{ID: in.Dev, User: "anna", ConfirmPub: pub, SessionPub: pub})
			v := &kg.Verifier{Devices: devs, Nonces: kg.NewNonces(), Now: func() time.Time { return time.UnixMilli(in.NowMs) }}
			if _, _, err := v.Verify(in.Signed, in.Type); err != nil {
				fmt.Println(err.Error())
			} else {
				fmt.Println("ok")
			}
		}
	}
}

// localCA — PKI для сценариев (в бою — OpenBao pki-device): подписывает CSR, CN = ID устройства от keyguard.
type localCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newLocalCA() *localCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test device CA"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return &localCA{k, c}
}

func (ca *localCA) Issue(_ context.Context, csrPEM, id string) (string, error) {
	b, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return "", err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: id},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(720 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
