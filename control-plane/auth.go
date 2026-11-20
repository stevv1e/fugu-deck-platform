package controlplane

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Вход на api.<домен>. Запрос принимается, только если сошлись три вещи, и все три — про один и тот же ключ
// сессии устройства (docs/ARCHITECTURE-v2.md, 3.3 «Каждый день»):
//   1. сертификат устройства — его проверил Traefik (mTLS) и передал в заголовке;
//   2. токен Keycloak, привязанный к ключу (cnf.jkt);
//   3. DPoP-доказательство на ЭТОТ запрос, подписанное тем же ключом.
// Украденного токена мало без ключа из чипа; украденного сертификата мало без токена.

// Identity — кто пришёл на api.
type Identity struct {
	User     string // preferred_username из токена Keycloak
	DeviceID string // CN сертификата: его задаёт keyguard, а не телефон
	JKT      string // отпечаток ключа сессии
}

var b64 = base64.RawURLEncoding

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

func ecThumbprint(x, y *big.Int) string {
	xb, yb := make([]byte, 32), make([]byte, 32)
	x.FillBytes(xb)
	y.FillBytes(yb)
	// RFC 7638: обязательные поля в алфавитном порядке, без пробелов
	h := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + b64.EncodeToString(xb) + `","y":"` + b64.EncodeToString(yb) + `"}`))
	return b64.EncodeToString(h[:])
}

func (j jwk) public() (crypto.PublicKey, error) {
	switch j.Kty {
	case "EC":
		if j.Crv != "P-256" {
			return nil, errors.New("кривая не P-256")
		}
		xb, e1 := b64.DecodeString(j.X)
		yb, e2 := b64.DecodeString(j.Y)
		if e1 != nil || e2 != nil || len(xb) != 32 || len(yb) != 32 {
			return nil, errors.New("координаты ключа")
		}
		pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		if _, err := pk.ECDH(); err != nil { // точка на кривой
			return nil, err
		}
		return pk, nil
	case "RSA":
		nb, e1 := b64.DecodeString(j.N)
		eb, e2 := b64.DecodeString(j.E)
		if e1 != nil || e2 != nil || len(nb) < 256 || len(eb) == 0 || len(eb) > 4 {
			return nil, errors.New("ключ RSA")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}, nil
	}
	return nil, errors.New("тип ключа")
}

// verifyJWS проверяет компактный JWS (RS256 или ES256) ключом, который по заголовку выбирает keyFor.
func verifyJWS(tok string, keyFor func(header map[string]any) (crypto.PublicKey, error)) (header, claims map[string]any, err error) {
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		return nil, nil, errors.New("не JWS")
	}
	hb, e1 := b64.DecodeString(p[0])
	cb, e2 := b64.DecodeString(p[1])
	sig, e3 := b64.DecodeString(p[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, nil, errors.New("base64url")
	}
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(cb, &claims) != nil {
		return nil, nil, errors.New("json")
	}
	pub, err := keyFor(header)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256([]byte(p[0] + "." + p[1]))
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if header["alg"] != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return nil, nil, errors.New("подпись")
		}
	case *ecdsa.PublicKey:
		if header["alg"] != "ES256" || len(sig) != 64 ||
			!ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, nil, errors.New("подпись")
		}
	default:
		return nil, nil, errors.New("тип ключа")
	}
	return header, claims, nil
}

// KeySet — ключи подписи токенов Keycloak (JWKS), с кэшем. Незнакомый kid заставляет перечитать, но не чаще раза в 30 с.
type KeySet struct {
	URL  string
	HTTP *http.Client

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
}

func (k *KeySet) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if pk, ok := k.keys[kid]; ok && time.Since(k.fetched) < time.Hour {
		return pk, nil
	}
	if k.keys != nil && time.Since(k.fetched) < 30*time.Second {
		return nil, errors.New("неизвестный kid")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.URL, nil)
	if err != nil {
		return nil, err
	}
	r, err := k.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var set struct{ Keys []jwk }
	if r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&set) != nil {
		return nil, fmt.Errorf("JWKS Keycloak: HTTP %d", r.StatusCode)
	}
	k.keys, k.fetched = map[string]crypto.PublicKey{}, time.Now()
	for _, j := range set.Keys {
		if j.Use == "enc" {
			continue
		}
		if pk, err := j.public(); err == nil {
			k.keys[j.Kid] = pk
		}
	}
	if pk, ok := k.keys[kid]; ok {
		return pk, nil
	}
	return nil, errors.New("неизвестный kid")
}

// replay — одноразовость jti DPoP-доказательств в окне их срока жизни.
// useNonce — DPoP jti одноразовый для всех реплик (общее хранилище); хранилище недоступно — хотя бы в этой реплике.
func (s *Server) useNonce(key string, now time.Time, ttl time.Duration) bool {
	ok, err := s.Store.UseNonce(key, now, now.Add(ttl))
	if err != nil {
		s.Log.Printf("event=nonce.store_failed err=%q", err.Error())
		return s.dpopSeen.use(key, now, ttl)
	}
	return ok && s.dpopSeen.use(key, now, ttl)
}

type replay struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func (r *replay) use(jti string, now time.Time, ttl time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[string]time.Time{}
	}
	if len(r.m) > 4096 {
		for k, exp := range r.m {
			if now.After(exp) {
				delete(r.m, k)
			}
		}
	}
	if exp, ok := r.m[jti]; ok && now.Before(exp) {
		return false
	}
	r.m[jti] = now.Add(ttl)
	return true
}

const (
	certHeader = "X-Forwarded-Tls-Client-Cert" // Traefik passTLSClientCert (pem: true)
	dpopWindow = 60 * time.Second
	clientID   = "deck-app"
)

// deviceCert разбирает сертификат устройства из заголовка Traefik: DER в base64, без строк BEGIN/END,
// возможно экранированный для URL; если сертификатов несколько (через запятую), лист — первый.
func deviceCert(h string) (*x509.Certificate, error) {
	if h == "" {
		return nil, errors.New("нет сертификата устройства")
	}
	// Traefik экранирует значение как параметр запроса (url.QueryEscape): «+» приходит как %2B. Раскодируем только
	// если экранирование есть — иначе QueryUnescape превратил бы «+» неэкранированного base64 в пробел.
	if strings.Contains(h, "%") {
		if u, err := url.QueryUnescape(h); err == nil {
			h = u
		}
	}
	h = strings.SplitN(h, ",", 2)[0]
	h = strings.NewReplacer("-----BEGIN CERTIFICATE-----", "", "-----END CERTIFICATE-----", "", "\n", "", "\r", "", " ", "").Replace(h)
	der, err := base64.StdEncoding.DecodeString(h)
	if err != nil {
		return nil, errors.New("сертификат устройства: base64")
	}
	return x509.ParseCertificate(der)
}

// Authenticate проверяет запрос к api.<домен>. htu — полный адрес запроса, как его видит телефон.
func (s *Server) Authenticate(r *http.Request, htu string) (*Identity, error) {
	now := s.now()
	// 1. сертификат устройства (цепочку до CA устройств уже проверил Traefik: без неё TLS не состоялся бы)
	cert, err := deviceCert(r.Header.Get(certHeader))
	if err != nil {
		return nil, err
	}
	ck, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || ck.Curve != elliptic.P256() {
		return nil, errors.New("сертификат устройства: нужен ключ P-256")
	}
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		return nil, errors.New("сертификат устройства истёк")
	}
	certJKT := ecThumbprint(ck.X, ck.Y)

	// 2. токен Keycloak
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "DPoP ") {
		return nil, errors.New("нужен токен: Authorization: DPoP …")
	}
	token := strings.TrimPrefix(auth, "DPoP ")
	_, cl, err := verifyJWS(token, func(h map[string]any) (crypto.PublicKey, error) {
		kid, _ := h["kid"].(string)
		return s.Keys.key(r.Context(), kid)
	})
	if err != nil {
		return nil, errors.New("токен: " + err.Error())
	}
	exp, _ := cl["exp"].(float64)
	cnf, _ := cl["cnf"].(map[string]any)
	user, _ := cl["preferred_username"].(string)
	switch {
	case cl["iss"] != s.Cfg.Issuer:
		return nil, errors.New("токен: чужой издатель")
	case cl["azp"] != clientID:
		return nil, errors.New("токен: выпущен не для приложения")
	case int64(exp) <= now.Unix():
		return nil, errors.New("токен: истёк")
	case cnf == nil || cnf["jkt"] != certJKT:
		return nil, errors.New("токен привязан не к ключу этого сертификата (cnf.jkt)")
	case !ValidNick(user):
		return nil, errors.New("токен: недопустимое имя пользователя")
	}

	// 3. DPoP: владение ключом на ЭТОТ запрос
	_, pc, err := verifyJWS(r.Header.Get("DPoP"), func(h map[string]any) (crypto.PublicKey, error) {
		if h["typ"] != "dpop+jwt" {
			return nil, errors.New("typ не dpop+jwt")
		}
		raw, _ := json.Marshal(h["jwk"])
		var j jwk
		if json.Unmarshal(raw, &j) != nil {
			return nil, errors.New("jwk")
		}
		pk, err := j.public()
		if err != nil {
			return nil, err
		}
		ek, ok := pk.(*ecdsa.PublicKey)
		if !ok || ecThumbprint(ek.X, ek.Y) != certJKT {
			return nil, errors.New("подписано не ключом устройства")
		}
		return pk, nil
	})
	if err != nil {
		return nil, errors.New("DPoP: " + err.Error())
	}
	iat, _ := pc["iat"].(float64)
	jti, _ := pc["jti"].(string)
	ath := sha256.Sum256([]byte(token))
	switch {
	case pc["htm"] != r.Method:
		return nil, errors.New("DPoP: другой метод")
	case pc["htu"] != htu:
		return nil, errors.New("DPoP: другой адрес")
	case pc["ath"] != b64.EncodeToString(ath[:]):
		return nil, errors.New("DPoP: другой токен")
	case now.Sub(time.Unix(int64(iat), 0)).Abs() > dpopWindow:
		return nil, errors.New("DPoP: устарело")
	case len(jti) < 8 || len(jti) > 128:
		return nil, errors.New("DPoP: jti")
	case !s.useNonce(certJKT+"/"+jti, now, 2*dpopWindow):
		return nil, errors.New("DPoP: повтор")
	}
	// 4. устройство не отозвано: сертификат живёт до своего срока, а отзыв действует сразу (revoked.go)
	if s.deviceRevoked(r.Context(), cert.Subject.CommonName) {
		return nil, errRevoked
	}
	return &Identity{User: user, DeviceID: cert.Subject.CommonName, JKT: certJKT}, nil
}
