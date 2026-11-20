package keyguard

// Регистрация устройства (architecture.md 3.3, шаги 5–7). Вызывает control-plane (маршрут join.<домен>/v1/enroll).
// Устройство регистрируется, только если сходятся три доказательства:
//  1. токен доступа Keycloak: подпись по JWKS realm, iss, azp=deck-app, срок; ПРИВЯЗАН к ключу сессии (cnf.jkt);
//  2. DPoP-доказательство ключом сессии на этот запрос (htm, htu, ath, свежий одноразовый jti);
//  3. действие device_enroll, подписанное ключом подтверждения (биометрия), — связывает оба ключа.
// Новое устройство НЕ подтверждено: подписывать действия не может, пока его не подтвердит другое устройство
// того же пользователя или администратор (device_approve). Исключение — первое устройство bootstrap-администратора.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type EnrollConfig struct {
	Issuer        string   // https://id.<домен>/realms/deck
	JWKSURL       string   // внутренний адрес JWKS Keycloak
	ClientID      string   // deck-app
	EnrollURL     string   // https://join.<домен>/v1/enroll — htu в DPoP-доказательстве
	StatusURL     string   // https://join.<домен>/v1/enroll/status — htu доказательства при запросе статуса
	Admins        []string // кто может подтверждать устройства других пользователей
	BootstrapUser string   // первое устройство этого пользователя подтверждается само, пока нет ни одного активного
	// Recover — восстановление администратора, потерявшего все устройства (включается через git на время): его
	// устройство подтверждается само, если у НЕГО нет действующих, даже когда в кластере они есть у других.
	// В режимах required/vouched — только устройство, прошедшее аттестацию.
	Recover bool
	HTTP    *http.Client

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
}

type JWK struct {
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

// Thumbprint — RFC 7638 (как jwkThumbprint в приложении).
func (j JWK) Thumbprint() string {
	var b []byte
	if j.Kty == "EC" {
		b = []byte(`{"crv":"` + j.Crv + `","kty":"EC","x":"` + j.X + `","y":"` + j.Y + `"}`)
	} else {
		b = []byte(`{"e":"` + j.E + `","kty":"RSA","n":"` + j.N + `"}`)
	}
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (j JWK) Public() (crypto.PublicKey, error) {
	switch j.Kty {
	case "EC":
		if j.Crv != "P-256" {
			return nil, errors.New("кривая не P-256")
		}
		x, e1 := base64.RawURLEncoding.DecodeString(j.X)
		y, e2 := base64.RawURLEncoding.DecodeString(j.Y)
		if e1 != nil || e2 != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("неверная точка")
		}
		pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pk.Curve.IsOnCurve(pk.X, pk.Y) {
			return nil, errors.New("точка не на кривой")
		}
		return pk, nil
	case "RSA":
		n, e1 := base64.RawURLEncoding.DecodeString(j.N)
		e, e2 := base64.RawURLEncoding.DecodeString(j.E)
		if e1 != nil || e2 != nil || len(n) < 256 {
			return nil, errors.New("неверный RSA-ключ (нужно ≥ 2048 бит)")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, errors.New("тип ключа не поддерживается")
}

// jws — разбор и проверка компактного JWS (только RS256 и ES256; "none" и HS* отвергаются).
func verifyJWS(tok string, key func(hdr map[string]any) (crypto.PublicKey, error)) (map[string]any, map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("не JWS")
	}
	hb, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, nil, errors.New("base64")
	}
	var hdr, claims map[string]any
	if json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(pb, &claims) != nil {
		return nil, nil, errors.New("json")
	}
	pub, err := key(hdr)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch hdr["alg"] {
	case "RS256":
		rk, ok := pub.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(rk, crypto.SHA256, h[:], sig) != nil {
			return nil, nil, errors.New("подпись токена неверна")
		}
	case "ES256":
		ek, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 || !ecdsa.Verify(ek, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, nil, errors.New("подпись токена неверна")
		}
	default:
		return nil, nil, fmt.Errorf("алгоритм %v не разрешён", hdr["alg"])
	}
	return hdr, claims, nil
}

func (c *EnrollConfig) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.keys[kid]; ok && time.Since(c.fetched) < 10*time.Minute {
		return k, nil
	}
	if time.Since(c.fetched) < 10*time.Second && c.keys != nil { // неизвестный kid — не чаще раза в 10 с
		return nil, errors.New("неизвестный kid")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", c.JWKSURL, nil)
	r, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var set struct{ Keys []JWK }
	if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
		return nil, err
	}
	c.keys, c.fetched = map[string]crypto.PublicKey{}, time.Now()
	for _, j := range set.Keys {
		if j.Use == "enc" {
			continue
		}
		if pk, err := j.Public(); err == nil {
			c.keys[j.Kid] = pk
		}
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("неизвестный kid")
}

func num64(v any) int64 {
	f, _ := v.(float64)
	return int64(f)
}

type enrollReq struct {
	AccessToken string          `json:"access_token"`
	DPoP        string          `json:"dpop"`
	SessionJWK  JWK             `json:"session_jwk"`
	ConfirmJWK  JWK             `json:"confirm_jwk"`
	Enroll      SignedAction    `json:"enroll"`
	Attestation json.RawMessage `json:"attestation,omitempty"`
	KeyStorage  string          `json:"key_storage,omitempty"`
	Challenge   string          `json:"challenge,omitempty"` // вызов из /v1/devices/challenge (base64url) — для аттестации
	CSR         string          `json:"csr"`
}

func DeviceIDFor(confirmJKT string) string { return "d-" + confirmJKT[:16] }

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if s.Enroll == nil {
		fail(w, 404, "регистрация не настроена")
		return
	}
	if c, err := s.caller(r); err != nil || c != s.ControlPlane {
		fail(w, 403, "только control-plane")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var q enrollReq
	if json.Unmarshal(body, &q) != nil {
		fail(w, 400, "json")
		return
	}
	now := s.Now()
	sessPub, e1 := q.SessionJWK.Public()
	confPub, e2 := q.ConfirmJWK.Public()
	if e1 != nil || e2 != nil || q.SessionJWK.Kty != "EC" || q.ConfirmJWK.Kty != "EC" {
		fail(w, 400, "ключи устройства: нужны P-256")
		return
	}
	sessJKT, confJKT := q.SessionJWK.Thumbprint(), q.ConfirmJWK.Thumbprint()
	if sessJKT == confJKT {
		fail(w, 400, "ключ сессии и ключ подтверждения должны различаться")
		return
	}
	// 1. токен Keycloak
	_, cl, err := verifyJWS(q.AccessToken, func(h map[string]any) (crypto.PublicKey, error) {
		kid, _ := h["kid"].(string)
		return s.Enroll.key(r.Context(), kid)
	})
	if err != nil {
		fail(w, 403, "токен: "+err.Error())
		return
	}
	cnf, _ := cl["cnf"].(map[string]any)
	switch {
	case cl["iss"] != s.Enroll.Issuer:
		fail(w, 403, "токен: чужой издатель")
		return
	case cl["azp"] != s.Enroll.ClientID:
		fail(w, 403, "токен: выпущен не для приложения")
		return
	case num64(cl["exp"]) <= now.Unix():
		fail(w, 403, "токен: истёк")
		return
	case cnf == nil || cnf["jkt"] != sessJKT:
		fail(w, 403, "токен не привязан к ключу сессии этого устройства (cnf.jkt)")
		return
	}
	user, _ := cl["preferred_username"].(string)
	if !safeSeg(user) {
		fail(w, 403, "токен: недопустимое имя пользователя")
		return
	}
	// 2. DPoP: владение ключом сессии на ЭТОТ запрос
	ph, pc, err := verifyJWS(q.DPoP, func(h map[string]any) (crypto.PublicKey, error) {
		if h["typ"] != "dpop+jwt" {
			return nil, errors.New("typ не dpop+jwt")
		}
		raw, _ := json.Marshal(h["jwk"])
		var j JWK
		if json.Unmarshal(raw, &j) != nil || j.Thumbprint() != sessJKT {
			return nil, errors.New("DPoP подписан не ключом сессии")
		}
		return sessPub, nil
	})
	_ = ph
	ath := sha256.Sum256([]byte(q.AccessToken))
	switch {
	case err != nil:
		fail(w, 403, "DPoP: "+err.Error())
		return
	case pc["htm"] != "POST" || pc["htu"] != s.Enroll.EnrollURL:
		fail(w, 403, "DPoP: не для этого запроса (htm/htu)")
		return
	case abs64(now.Unix()-num64(pc["iat"])) > 300:
		fail(w, 403, "DPoP: устарело")
		return
	case pc["ath"] != base64.RawURLEncoding.EncodeToString(ath[:]):
		fail(w, 403, "DPoP: не для этого токена (ath)")
		return
	}
	if jti, _ := pc["jti"].(string); len(jti) < 12 || !s.Verifier.Nonces.Use("dpop", jti, now) {
		fail(w, 403, "DPoP: повтор")
		return
	}
	// 3. действие device_enroll, подписанное ключом подтверждения
	// Тот же JWS, что у остальных действий (actions.go), но устройства ещё нет в реестре: подпись проверяется
	// ключом подтверждения из запроса, а kid и device_id обязаны совпасть с ID, который keyguard выводит из него.
	j, err := openJWS(q.Enroll)
	if err != nil || !j.signedBy(confPub.(*ecdsa.PublicKey)) {
		fail(w, 403, "подпись регистрации ключом подтверждения неверна")
		return
	}
	a := j.action
	if err := ValidateAction(a); err != nil {
		fail(w, 403, err.Error())
		return
	}
	ts, _ := strconv.ParseInt(num(a, "ts"), 10, 64)
	if s_(a, "type") != "device_enroll" || s_(a, "session_jkt") != sessJKT || s_(a, "confirm_jkt") != confJKT ||
		j.kid != DeviceIDFor(confJKT) || s_(a, "device_id") != j.kid {
		fail(w, 403, "регистрация: поля не совпадают с ключами")
		return
	}
	if at := time.Unix(ts, 0); now.Sub(at) > MaxAge || at.Sub(now) > MaxFuture {
		fail(w, 403, "регистрация: устарела")
		return
	}
	if !s.Verifier.Nonces.Use("enroll|"+confJKT, s_(a, "nonce"), now) {
		fail(w, 403, "регистрация: повтор")
		return
	}
	if err := checkCSR(q.CSR, sessPub.(*ecdsa.PublicKey)); err != nil {
		fail(w, 403, err.Error())
		return
	}
	id := DeviceIDFor(confJKT)
	if _, exists := s.Verifier.Devices.Get(id); exists {
		fail(w, 409, "устройство уже зарегистрировано")
		return
	}
	// 4. аттестация: ключи созданы в чипе настоящего телефона настоящим приложением (attest.go)
	attested, err := s.checkAttestation(&q, sessPub.(*ecdsa.PublicKey), confPub.(*ecdsa.PublicKey), sessJKT, confJKT, now)
	if err != nil {
		s.Log.Printf("event=device.attestation_rejected user=%s reason=%q", uid(user), err.Error())
		fail(w, 403, err.Error())
		return
	}
	if attested != nil && attested.Format == "android-key" {
		q.KeyStorage = attested.Level // место хранения — из аттестации, а не со слов приложения
	}
	boot := s.Enroll.BootstrapUser != "" && user == s.Enroll.BootstrapUser
	recovering := boot && s.Enroll.Recover && s.Verifier.Devices.AnyActive() && !s.Verifier.Devices.AnyActiveOf(user)
	pending := !(boot && (!s.Verifier.Devices.AnyActive() || recovering)) ||
		s.Attest.NeedsVoucher(attested.String()) // без аттестации — только через подтверждение (handleDeviceAction)
	if recovering && !pending {
		s.Log.Printf("event=device.bootstrap_recover user=%s device=%s attested=%q", user, id, attested.String())
	}
	dev := &Device{ID: id, User: user, SessionPub: sessPub.(*ecdsa.PublicKey), ConfirmPub: confPub.(*ecdsa.PublicKey),
		Pending: true, Name: s_(a, "name"), KeyStorage: q.KeyStorage, Attested: attested.String(), CSR: q.CSR}
	if err := s.Verifier.Devices.Add(dev); err != nil {
		s.stateFail(w, "device.add", err)
		return
	}
	if !pending { // bootstrap-администратор: сертификат сразу; не выпустился — остаётся ждать подтверждения
		if err := s.issueFor(r.Context(), dev); err != nil {
			s.Log.Printf("event=device.cert_failed device=%s err=%q", id, err.Error())
			pending = true
		} else if err := s.Verifier.Devices.Activate(id); err != nil {
			s.Log.Printf("event=state.error op=device.activate err=%q", err.Error())
			pending = true
		}
	}
	status := "pending"
	if !pending {
		status = "active"
	}
	s.Log.Printf("event=device.enroll user=%s device=%s status=%s storage=%s attested=%q", user, id, status, q.KeyStorage, dev.Attested)
	json.NewEncoder(w).Encode(map[string]string{"device_id": id, "user": user, "status": status, "attested": dev.Attested})
}

// POST /v1/devices/challenge — одноразовый вызов для аттестации (control-plane, маршрут join/v1/enroll/challenge).
// Приложение берёт его ДО создания ключей: вызов попадает внутрь аттестации.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if s.Enroll == nil || s.Attest == nil || s.Attest.Mode == "off" {
		fail(w, 404, "аттестация не настроена")
		return
	}
	if c, err := s.caller(r); err != nil || c != s.ControlPlane {
		fail(w, 403, "только control-plane")
		return
	}
	if r.Method != http.MethodPost {
		fail(w, 405, "POST")
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"challenge": base64.RawURLEncoding.EncodeToString(s.Attest.NewChallenge(s.Now())),
		"expires_in": int(ChallengeTTL.Seconds())})
}

// checkAttestation: nil, nil — аттестации нет и политика её не требует.
func (s *Server) checkAttestation(q *enrollReq, sess, conf *ecdsa.PublicKey, sessJKT, confJKT string, now time.Time) (*AttestResult, error) {
	p := s.Attest
	if p == nil || p.Mode == "off" {
		return nil, nil
	}
	none := len(bytes.TrimSpace(q.Attestation)) == 0 || string(bytes.TrimSpace(q.Attestation)) == "null"
	if none {
		return p.Verify(nil, sess, conf, sessJKT, confJKT, nil, now) // "required" → отказ, "optional" → без аттестации
	}
	ch, err := base64.RawURLEncoding.DecodeString(q.Challenge)
	if err != nil {
		return nil, fmt.Errorf("%w: нет вызова", ErrAttestation)
	}
	until, err := p.checkChallenge(ch, now)
	if err != nil {
		return nil, err
	}
	res, err := p.Verify(q.Attestation, sess, conf, sessJKT, confJKT, ch, now)
	if err != nil {
		return nil, err
	}
	// вызов расходуется ПОСЛЕДНИМ и помнится до своего истечения: одну аттестацию нельзя предъявить дважды
	if !s.Verifier.Nonces.UseUntil("attest", q.Challenge, now, until) {
		return nil, fmt.Errorf("%w: вызов уже использован", ErrAttestation)
	}
	return res, nil
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// device_approve / device_revoke (типы действий приложения, actions.ts): подписывает активное устройство того же пользователя или администратора.
func (s *Server) handleDeviceAction(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := s.caller(r); err != nil || c != s.ControlPlane {
			fail(w, 403, "только control-plane")
			return
		}
		body, ok := s.readBody(w, r)
		if !ok {
			return
		}
		var sa SignedAction
		if json.Unmarshal(body, &sa) != nil {
			fail(w, 400, "json")
			return
		}
		a, by, err := s.Verifier.Verify(sa, map[string]string{"confirm": "device_approve", "revoke": "device_revoke"}[kind])
		if err != nil {
			fail(w, 403, err.Error())
			return
		}
		target, ok := s.Verifier.Devices.Get(s_(a, "target"))
		if !ok {
			fail(w, 404, "устройство не найдено")
			return
		}
		// Человек подтверждал, глядя на пользователя (и имя устройства) из действия — они обязаны совпасть с реестром:
		// иначе control-plane мог бы показать «телефон Анны», а подставить id устройства Мэллори.
		if s_(a, "user") != target.User || (kind == "confirm" && s_(a, "name") != target.Name) {
			fail(w, 403, "действие описывает другое устройство (пользователь или имя не совпадают)")
			return
		}
		admin := s.Enroll != nil && contains(s.Enroll.Admins, by.User)
		if target.User != by.User && !admin {
			fail(w, 403, "подтверждать и отзывать чужие устройства может только администратор")
			return
		}
		if kind == "confirm" {
			if !target.Pending || target.Revoked {
				fail(w, 409, "устройство не ожидает подтверждения")
				return
			}
			if s.Attest.NeedsVoucher(target.Attested) && by.Attested == "" {
				fail(w, 403, "устройство без аттестации подтверждается только с устройства, прошедшего аттестацию (телефон с ключами в чипе)")
				return
			}
			if err := s.issueFor(r.Context(), target); err != nil { // без сертификата не активируем
				s.Log.Printf("event=device.cert_failed device=%s err=%q", target.ID, err.Error())
				fail(w, 502, "не удалось выпустить сертификат устройства")
				return
			}
			if err := s.Verifier.Devices.Activate(target.ID); err != nil {
				s.stateFail(w, "device.activate", err)
				return
			}
		} else if err := s.Verifier.Devices.Revoke(target.ID); err != nil {
			// в памяти устройство уже отозвано, но перезапуск этого не переживёт — клиент должен повторить
			s.stateFail(w, "device.revoke", err)
			return
		}
		s.Log.Printf("event=device.%s device=%s user=%s by=%s", kind, target.ID, target.User, by.User)
		w.Write([]byte(`{"ok":true}`))
	}
}

// handleDeviceList — устройства пользователя для экрана «Устройства» в приложении. Спрашивает control-plane от имени
// уже опознанного пользователя (user). Администратор видит устройства всех: ему подтверждать первые устройства
// приглашённых. Отдаётся только то, что человек и так видит на карточке подтверждения, — ключей здесь нет.
func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	if c, err := s.caller(r); err != nil || c != s.ControlPlane {
		fail(w, 403, "только control-plane")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var q struct {
		User string `json:"user"`
	}
	if json.Unmarshal(body, &q) != nil || q.User == "" {
		fail(w, 400, "json")
		return
	}
	admin := s.Enroll != nil && contains(s.Enroll.Admins, q.User)
	filter := q.User
	if admin {
		filter = ""
	}
	type item struct {
		ID         string `json:"id"`
		User       string `json:"user"`
		Name       string `json:"name"`
		Status     string `json:"status"` // pending | active | revoked
		KeyStorage string `json:"key_storage,omitempty"`
		Attested   string `json:"attested,omitempty"`
	}
	out := []item{}
	for _, d := range s.Verifier.Devices.List(filter) {
		st := "active"
		switch {
		case d.Revoked:
			st = "revoked"
		case d.Pending:
			st = "pending"
		}
		out = append(out, item{d.ID, d.User, d.Name, st, d.KeyStorage, d.Attested})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"devices": out, "admin": admin})
}

// handleDeviceRevoked — ID отозванных устройств для control-plane: он держит копию и не пускает их на api сразу,
// не дожидаясь конца срока сертификата устройства. Только ID — ни пользователей, ни имён.
func (s *Server) handleDeviceRevoked(w http.ResponseWriter, r *http.Request) {
	if c, err := s.caller(r); err != nil || c != s.ControlPlane {
		fail(w, 403, "только control-plane")
		return
	}
	ids := []string{}
	for _, d := range s.Verifier.Devices.List("") {
		if d.Revoked {
			ids = append(ids, d.ID)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"revoked": ids})
}
