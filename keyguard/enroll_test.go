package keyguard

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ecJWK(k *ecdsa.PublicKey) JWK {
	return JWK{Kty: "EC", Crv: "P-256", X: b64u.EncodeToString(k.X.FillBytes(make([]byte, 32))), Y: b64u.EncodeToString(k.Y.FillBytes(make([]byte, 32)))}
}

func jwsES(k *ecdsa.PrivateKey, hdr, claims map[string]any) string {
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	in := b64u.EncodeToString(h) + "." + b64u.EncodeToString(c)
	d := sha256.Sum256([]byte(in))
	r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
	return in + "." + b64u.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func jwsRS(k *rsa.PrivateKey, kid string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	c, _ := json.Marshal(claims)
	in := b64u.EncodeToString(h) + "." + b64u.EncodeToString(c)
	d := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	return in + "." + b64u.EncodeToString(sig)
}

type idp struct {
	key   *rsa.PrivateKey
	iss   string
	srv   *httptest.Server
	clock func() time.Time
}

func newIdP(t *testing.T, clock func() time.Time) *idp {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := &idp{key: k, clock: clock}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64u.EncodeToString(k.N.Bytes()), "e": b64u.EncodeToString([]byte{1, 0, 1})}}})
	}))
	t.Cleanup(p.srv.Close)
	p.iss = "https://id.deck.test/realms/deck"
	return p
}

func (p *idp) token(user, jkt string, mut func(map[string]any)) string {
	c := map[string]any{"iss": p.iss, "azp": "deck-app", "preferred_username": user, "exp": p.clock().Add(5 * time.Minute).Unix(),
		"iat": p.clock().Unix(), "cnf": map[string]any{"jkt": jkt}, "typ": "Bearer"}
	if mut != nil {
		mut(c)
	}
	return jwsRS(p.key, "k1", c)
}

type newDev struct {
	sess, conf *ecdsa.PrivateKey
}

func mkDev() newDev {
	s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return newDev{s, c}
}

const enrollURL = "https://join.deck.test/v1/enroll"

var jtiN int

func (d newDev) proof(tok string, now time.Time, mut func(h, c map[string]any)) string {
	jtiN++
	ath := sha256.Sum256([]byte(tok))
	h := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": ecJWK(&d.sess.PublicKey)}
	c := map[string]any{"htm": "POST", "htu": enrollURL, "iat": now.Unix(), "jti": fmt.Sprintf("jti-%012d", jtiN), "ath": b64u.EncodeToString(ath[:])}
	if mut != nil {
		mut(h, c)
	}
	return jwsES(d.sess, h, c)
}

func (d newDev) enrollAction(now time.Time, signer *ecdsa.PrivateKey, mut func(map[string]any)) SignedAction {
	jtiN++
	id := DeviceIDFor(ecJWK(&d.conf.PublicKey).Thumbprint())
	a := map[string]any{"type": "device_enroll", "session_jkt": ecJWK(&d.sess.PublicKey).Thumbprint(),
		"confirm_jkt": ecJWK(&d.conf.PublicKey).Thumbprint(), "name": "iPhone", "device_id": id,
		"nonce": fmt.Sprintf("enroll-nonce-%08d", jtiN), "ts": json.Number(fmt.Sprint(now.Unix()))}
	if mut != nil {
		mut(a)
	}
	if signer == nil {
		signer = d.conf
	}
	return SignedAction{JWS: jwsOf(Canonical(a), id, signer)}
}

func csrFor(k *ecdsa.PrivateKey) string {
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "fugu-deck device"}}, k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func (d newDev) req(tok, proof string, sa SignedAction) []byte {
	return d.reqCSR(tok, proof, sa, csrFor(d.sess))
}

func (d newDev) reqCSR(tok, proof string, sa SignedAction, csr string) []byte {
	return j(map[string]any{"access_token": tok, "dpop": proof, "session_jwk": ecJWK(&d.sess.PublicKey),
		"confirm_jwk": ecJWK(&d.conf.PublicKey), "enroll": sa, "key_storage": "secure_enclave", "csr": csr})
}

type fakeCA struct {
	issued []string
	fail   bool
}

func (f *fakeCA) Issue(_ context.Context, csrPEM, id string) (string, error) {
	if f.fail {
		return "", fmt.Errorf("pki недоступна")
	}
	f.issued = append(f.issued, id)
	return "-----BEGIN CERTIFICATE-----\nCN=" + id + "\n-----END CERTIFICATE-----\n", nil
}

const statusURL = "https://join.deck.test/v1/enroll/status"

func (d newDev) statusReq(id string, now time.Time, key *ecdsa.PrivateKey) []byte {
	jtiN++
	if key == nil {
		key = d.sess
	}
	pr := jwsES(key, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": ecJWK(&key.PublicKey)},
		map[string]any{"htm": "POST", "htu": statusURL, "iat": now.Unix(), "jti": fmt.Sprintf("st-jti-%08d", jtiN)})
	return j(map[string]any{"device_id": id, "proof": pr})
}

func TestAttack_Enroll(t *testing.T) {
	k := newRig(t)
	k.srv.Verifier.Devices = NewDevices() // пустой реестр: регистрация с нуля
	p := newIdP(t, k.now)
	ca := &fakeCA{}
	k.srv.Certs = ca
	k.srv.Enroll = &EnrollConfig{Issuer: p.iss, JWKSURL: p.srv.URL, ClientID: "deck-app", EnrollURL: enrollURL, StatusURL: statusURL,
		Admins: []string{"admin"}, BootstrapUser: "admin", HTTP: http.DefaultClient}
	c := &check{t: t}
	now := k.now()
	enroll := func(d newDev, user string, tokMut func(map[string]any), prMut func(h, c map[string]any), sa *SignedAction) (int, map[string]string) {
		tok := p.token(user, ecJWK(&d.sess.PublicKey).Thumbprint(), tokMut)
		a := d.enrollAction(now, nil, nil)
		if sa != nil {
			a = *sa
		}
		st, body := k.do("POST", "/v1/devices", "tok-cp", d.req(tok, d.proof(tok, now, prMut), a), nil)
		var m map[string]string
		json.Unmarshal([]byte(body), &m)
		if st != 200 {
			m = map[string]string{"error": body}
		}
		return st, m
	}

	// bootstrap: первое устройство администратора подтверждается само
	adm := mkDev()
	st, m := enroll(adm, "admin", nil, nil, nil)
	c.ok("E1 первое устройство bootstrap-администратора активно сразу", st == 200 && m["status"] == "active", st, m)
	adm2 := mkDev()
	st, m = enroll(adm2, "admin", nil, nil, nil)
	c.ok("E2 второе устройство администратора — уже ожидает подтверждения", st == 200 && m["status"] == "pending", st, m)

	anna := mkDev()
	st, m = enroll(anna, "anna", nil, nil, nil)
	annaID := m["device_id"]
	c.ok("E3 устройство Анны зарегистрировано, ожидает подтверждения", st == 200 && m["status"] == "pending" && annaID == DeviceIDFor(ecJWK(&anna.conf.PublicKey).Thumbprint()), st, m)

	// неподтверждённое устройство ничего не подписывает
	ph := &phone{dev: &Device{ID: annaID, User: "anna"}, confirm: anna.conf}
	st, body := k.do("POST", "/v1/grants/revoke", "tok-cp", j(ph.sign(t, k, map[string]any{"type": "grant_revoke", "space": "t-shop", "chat": "c-1", "proposal": "p-1"}, nil)), nil)
	c.ok("E4 неподтверждённое устройство не может подписывать действия", st == 403 && strings.Contains(body, "не подтверждено"), st, body)

	// подтверждение: чужой не-админ нельзя, админ — можно
	bob := mkDev()
	_, mb := enroll(bob, "bob", nil, nil, nil)
	admPh := &phone{dev: &Device{ID: DeviceIDFor(ecJWK(&adm.conf.PublicKey).Thumbprint()), User: "admin"}, confirm: adm.conf}
	k.srv.Verifier.Devices.Activate(mb["device_id"]) // Боба уже подтвердили
	bobPh := &phone{dev: &Device{ID: mb["device_id"], User: "bob"}, confirm: bob.conf}
	st, _ = k.do("POST", "/v1/devices/confirm", "tok-cp", j(bobPh.sign(t, k, map[string]any{"type": "device_approve", "user": "anna", "target": annaID, "name": "iPhone"}, nil)), nil)
	c.ok("E5 Боб (не админ) не может подтвердить устройство Анны", st == 403, st)
	// администратору показали одно устройство, а подставили id другого: user и name сверяются с реестром
	st, _ = k.do("POST", "/v1/devices/confirm", "tok-cp", j(admPh.sign(t, k, map[string]any{"type": "device_approve", "user": "bob", "target": annaID, "name": "iPhone"}, nil)), nil)
	st2, _ := k.do("POST", "/v1/devices/confirm", "tok-cp", j(admPh.sign(t, k, map[string]any{"type": "device_approve", "user": "anna", "target": annaID, "name": "iPad"}, nil)), nil)
	dvA, _ := k.srv.Verifier.Devices.Get(annaID)
	c.ok("E5b подтверждение с чужим пользователем или другим именем устройства отклонено, устройство не активировано", st == 403 && st2 == 403 && dvA.Pending, st, st2)
	st, body = k.do("POST", "/v1/devices/confirm", "tok-cp", j(admPh.sign(t, k, map[string]any{"type": "device_approve", "user": "anna", "target": annaID, "name": "iPhone", "note": "x"}, nil)), nil)
	c.ok("E5c лишнее поле в подписанном действии отклонено схемой", st == 403 && strings.Contains(body, "лишнее поле"), st, body)
	st, _ = k.do("POST", "/v1/devices/confirm", "tok-cp", j(admPh.sign(t, k, map[string]any{"type": "device_approve", "user": "anna", "target": annaID, "name": "iPhone"}, nil)), nil)
	c.ok("E6 администратор подтверждает устройство Анны", st == 200, st)
	_, _, err := k.srv.Verifier.Verify(ph.sign(t, k, map[string]any{"type": "account_delete", "user": "anna"}, nil), "account_delete")
	c.ok("E7b подпись активного устройства Анны проходит проверку", err == nil, err)

	// подделки токена
	bad := func(name string, d newDev, user string, tokMut func(map[string]any), prMut func(h, c map[string]any), sa *SignedAction, want string) {
		st, m := enroll(d, user, tokMut, prMut, sa)
		c.ok(name, st == 403 && strings.Contains(m["error"], want), st, m["error"])
	}
	other := mkDev()
	bad("E8 токен привязан к ДРУГОМУ ключу сессии (украден с чужого телефона)", mkDev(), "eve",
		func(cl map[string]any) { cl["cnf"] = map[string]any{"jkt": ecJWK(&other.sess.PublicKey).Thumbprint()} }, nil, nil, "cnf.jkt")
	bad("E9 токен без привязки (обычный Bearer)", mkDev(), "eve", func(cl map[string]any) { delete(cl, "cnf") }, nil, nil, "cnf.jkt")
	bad("E10 чужой издатель", mkDev(), "eve", func(cl map[string]any) { cl["iss"] = "https://evil/realms/deck" }, nil, nil, "издатель")
	bad("E11 токен другого клиента (не deck-app)", mkDev(), "eve", func(cl map[string]any) { cl["azp"] = "admin-cli" }, nil, nil, "не для приложения")
	bad("E12 истёкший токен", mkDev(), "eve", func(cl map[string]any) { cl["exp"] = now.Add(-time.Minute).Unix() }, nil, nil, "истёк")
	bad("E13 недопустимое имя пользователя (обход пути)", mkDev(), "../admin", nil, nil, nil, "имя")
	{ // токен подписан чужим RSA-ключом с тем же kid
		d := mkDev()
		ek, _ := rsa.GenerateKey(rand.Reader, 2048)
		tok := jwsRS(ek, "k1", map[string]any{"iss": p.iss, "azp": "deck-app", "preferred_username": "eve", "exp": now.Add(time.Minute).Unix(),
			"cnf": map[string]any{"jkt": ecJWK(&d.sess.PublicKey).Thumbprint()}})
		st, body := k.do("POST", "/v1/devices", "tok-cp", d.req(tok, d.proof(tok, now, nil), d.enrollAction(now, nil, nil)), nil)
		c.ok("E14 токен подписан чужим ключом с тем же kid", st == 403 && strings.Contains(body, "подпись"), st, body)
	}
	for _, alg := range []string{"none", "HS256"} {
		d := mkDev()
		h, _ := json.Marshal(map[string]any{"alg": alg, "kid": "k1"})
		cl, _ := json.Marshal(map[string]any{"iss": p.iss, "azp": "deck-app", "preferred_username": "eve", "exp": now.Add(time.Minute).Unix(),
			"cnf": map[string]any{"jkt": ecJWK(&d.sess.PublicKey).Thumbprint()}})
		in := b64u.EncodeToString(h) + "." + b64u.EncodeToString(cl)
		mac := hmac.New(sha256.New, []byte("публичный ключ как секрет"))
		mac.Write([]byte(in))
		tok := in + "." + b64u.EncodeToString(mac.Sum(nil))
		st, body := k.do("POST", "/v1/devices", "tok-cp", d.req(tok, d.proof(tok, now, nil), d.enrollAction(now, nil, nil)), nil)
		c.ok("E15 алгоритм "+alg+" отвергается", st == 403 && strings.Contains(body, "не разрешён"), st, body)
	}

	// подделки DPoP
	bad("E16 DPoP подписан не ключом сессии", mkDev(), "eve", nil, func(h, c map[string]any) { h["jwk"] = ecJWK(&other.sess.PublicKey) }, nil, "не ключом сессии")
	bad("E17 DPoP для другого адреса (htu api)", mkDev(), "eve", nil, func(h, c map[string]any) { c["htu"] = "https://api.deck.test/v1/enroll" }, nil, "htu")
	bad("E18 DPoP для другого метода", mkDev(), "eve", nil, func(h, c map[string]any) { c["htm"] = "GET" }, nil, "htm")
	bad("E19 DPoP для другого токена (ath)", mkDev(), "eve", nil, func(h, c map[string]any) { c["ath"] = "AAAA" }, nil, "ath")
	bad("E20 DPoP устарел", mkDev(), "eve", nil, func(h, c map[string]any) { c["iat"] = now.Add(-10 * time.Minute).Unix() }, nil, "устарело")
	bad("E21 DPoP без typ dpop+jwt", mkDev(), "eve", nil, func(h, c map[string]any) { h["typ"] = "JWT" }, nil, "typ")
	{
		d := mkDev()
		tok := p.token("eve", ecJWK(&d.sess.PublicKey).Thumbprint(), nil)
		pr := d.proof(tok, now, nil)
		k.do("POST", "/v1/devices", "tok-cp", d.req(tok, pr, d.enrollAction(now, nil, nil)), nil)
		st, body := k.do("POST", "/v1/devices", "tok-cp", d.req(tok, pr, d.enrollAction(now, nil, nil)), nil)
		c.ok("E22 повтор того же DPoP (jti)", st == 403 && strings.Contains(body, "повтор"), st, body)
	}

	// подделки действия регистрации
	{
		d := mkDev()
		sa := d.enrollAction(now, d.sess, nil)
		bad("E23 регистрация подписана ключом СЕССИИ (без биометрии)", d, "eve", nil, nil, &sa, "подтверждения")
	}
	{
		d := mkDev()
		sa := d.enrollAction(now, nil, func(a map[string]any) { a["confirm_jkt"] = ecJWK(&other.conf.PublicKey).Thumbprint() })
		bad("E24 действие регистрации для другого ключа подтверждения", d, "eve", nil, nil, &sa, "не совпадают")
	}
	{
		d := mkDev()
		sa := d.enrollAction(now, nil, func(a map[string]any) { a["ts"] = json.Number(fmt.Sprint(now.Add(-10 * time.Minute).Unix())) })
		bad("E25 старое действие регистрации", d, "eve", nil, nil, &sa, "устарела")
	}
	{
		d := mkDev()
		d.conf = d.sess
		st, _ := enroll(d, "eve", nil, nil, nil)
		c.ok("E26 один ключ вместо двух (сессия = подтверждение) — 400", st == 400, st)
	}
	st, _ = enroll(anna, "anna", nil, nil, nil)
	c.ok("E27 повторная регистрация того же устройства — 409", st == 409, st)
	{
		d := mkDev()
		tok := p.token("eve", ecJWK(&d.sess.PublicKey).Thumbprint(), nil)
		st, _ := k.do("POST", "/v1/devices", "tok-anna", d.req(tok, d.proof(tok, now, nil), d.enrollAction(now, nil, nil)), nil)
		c.ok("E28 регистрация не от control-plane — 403", st == 403, st)
	}

	// отзыв
	st, _ = k.do("POST", "/v1/devices/revoke", "tok-cp", j(bobPh.sign(t, k, map[string]any{"type": "device_revoke", "user": "anna", "target": annaID}, nil)), nil)
	c.ok("E29 Боб не может отозвать устройство Анны", st == 403, st)
	st, _ = k.do("POST", "/v1/devices/revoke", "tok-cp", j(admPh.sign(t, k, map[string]any{"type": "device_revoke", "user": "anna", "target": annaID}, nil)), nil)
	_, _, err = k.srv.Verifier.Verify(ph.sign(t, k, map[string]any{"type": "account_delete", "user": "anna"}, nil), "account_delete")
	c.ok("E30 администратор отозвал — подписи Анны сразу не принимаются", st == 200 && err == ErrRevoked, st, err)
	// ---- CSR и сертификат устройства ----
	{
		d := mkDev()
		tok := p.token("eve", ecJWK(&d.sess.PublicKey).Thumbprint(), nil)
		evilKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		st, body := k.do("POST", "/v1/devices", "tok-cp", d.reqCSR(tok, d.proof(tok, now, nil), d.enrollAction(now, nil, nil), csrFor(evilKey)), nil)
		c.ok("E31 CSR с ключом не той сессии (сертификат на ключ злоумышленника)", st == 403 && strings.Contains(body, "не совпадает"), st, body)
		bad := csrFor(d.sess)
		bad = strings.Replace(bad, bad[60:64], "AAAA", 1)
		st, body = k.do("POST", "/v1/devices", "tok-cp", d.reqCSR(tok, d.proof(tok, now, nil), d.enrollAction(now, nil, nil), bad), nil)
		c.ok("E32 повреждённый CSR", st == 403 && strings.Contains(body, "CSR"), st, body)
		st, body = k.do("POST", "/v1/devices", "tok-cp", d.reqCSR(tok, d.proof(tok, now, nil), d.enrollAction(now, nil, nil), ""), nil)
		c.ok("E33 регистрация без CSR", st == 403 && strings.Contains(body, "CSR"), st, body)
	}
	c.ok("E34 bootstrap-администратор получил сертификат сразу", len(ca.issued) > 0 && ca.issued[0] == DeviceIDFor(ecJWK(&adm.conf.PublicKey).Thumbprint()), ca.issued)
	carl := mkDev()
	_, mc := enroll(carl, "carl", nil, nil, nil)
	carlID := mc["device_id"]
	_, body = k.do("POST", "/v1/devices/status", "tok-cp", carl.statusReq(carlID, now, nil), nil)
	c.ok("E35 до подтверждения: статус pending, сертификата нет", strings.Contains(body, `"pending"`) && !strings.Contains(body, "CERTIFICATE"), body)
	ca.fail = true
	st, _ = k.do("POST", "/v1/devices/confirm", "tok-cp", j(admPh.sign(t, k, map[string]any{"type": "device_approve", "user": "carl", "target": carlID, "name": "iPhone"}, nil)), nil)
	dv, _ := k.srv.Verifier.Devices.Get(carlID)
	c.ok("E36 PKI недоступна — устройство НЕ активируется без сертификата", st == 502 && dv.Pending, st)
	ca.fail = false
	st, _ = k.do("POST", "/v1/devices/confirm", "tok-cp", j(admPh.sign(t, k, map[string]any{"type": "device_approve", "user": "carl", "target": carlID, "name": "iPhone"}, nil)), nil)
	_, body = k.do("POST", "/v1/devices/status", "tok-cp", carl.statusReq(carlID, now, nil), nil)
	c.ok("E37 после подтверждения: active + сертификат", st == 200 && strings.Contains(body, `"active"`) && strings.Contains(body, "CN="+carlID), st, body)
	thief, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	st, body = k.do("POST", "/v1/devices/status", "tok-cp", carl.statusReq(carlID, now, thief), nil)
	c.ok("E38 сертификат чужого устройства не выдаётся (доказательство не его ключом)", st == 403 && !strings.Contains(body, "CERTIFICATE"), st)
	sr := carl.statusReq(carlID, now, nil)
	k.do("POST", "/v1/devices/status", "tok-cp", sr, nil)
	st, _ = k.do("POST", "/v1/devices/status", "tok-cp", sr, nil)
	c.ok("E39 повтор доказательства статуса", st == 403, st)
	k.do("POST", "/v1/devices/revoke", "tok-cp", j(admPh.sign(t, k, map[string]any{"type": "device_revoke", "user": "carl", "target": carlID}, nil)), nil)
	_, body = k.do("POST", "/v1/devices/status", "tok-cp", carl.statusReq(carlID, now, nil), nil)
	c.ok("E40 отозванное устройство: revoked, сертификат не отдаётся", strings.Contains(body, `"revoked"`) && !strings.Contains(body, "CERTIFICATE"), body)

	// ---- список устройств и приглашения из приложения ----
	list := func(tok, user string) (int, bool, map[string]string) {
		st, body := k.do("POST", "/v1/devices/list", tok, j(map[string]string{"user": user}), nil)
		var out struct {
			Admin   bool `json:"admin"`
			Devices []struct{ ID, User, Status string }
		}
		json.Unmarshal([]byte(body), &out)
		m := map[string]string{}
		for _, d := range out.Devices {
			m[d.ID] = d.User + "/" + d.Status
		}
		if strings.Contains(body, "Pub") || strings.Contains(body, "CSR") || strings.Contains(body, "CERTIFICATE") {
			t.Errorf("список устройств отдаёт ключи или сертификаты: %s", body)
		}
		return st, out.Admin, m
	}
	st, isAdm, devs := list("tok-cp", "bob")
	c.ok("E41 пользователь видит только свои устройства", st == 200 && !isAdm && len(devs) == 1 && devs[bobPh.dev.ID] == "bob/active", st, devs)
	st, isAdm, devs = list("tok-cp", "admin")
	c.ok("E42 администратор видит устройства всех, со статусами", st == 200 && isAdm && devs[annaID] == "anna/revoked" &&
		devs[carlID] == "carl/revoked" && devs[admPh.dev.ID] == "admin/active" && devs[bobPh.dev.ID] == "bob/active", st, devs)
	st, _, _ = list("tok-anna", "admin")
	c.ok("E43 список устройств не от control-plane — 403", st == 403, st)
	inv := func(tok string, by *phone, user string) (int, string) {
		return k.do("POST", "/v1/actions/verify", tok, j(by.sign(t, k, map[string]any{"type": "invite_create", "user": user}, nil)), nil)
	}
	st, body = inv("tok-cp", bobPh, "bob")
	c.ok("E44 приглашение себе (ещё одно устройство) — проходит", st == 200 && strings.Contains(body, `"user":"bob"`), st, body)
	st, body = inv("tok-cp", bobPh, "dave")
	c.ok("E45 приглашение другому от не-администратора — 403", st == 403 && strings.Contains(body, "администратор"), st, body)
	st, _ = inv("tok-cp", admPh, "dave")
	c.ok("E46 администратор приглашает нового пользователя", st == 200, st)
	st, _ = inv("tok-cp", ph, "anna")
	c.ok("E47 приглашение с отозванного устройства — 403", st == 403, st)
	st, _ = inv("tok-anna", admPh, "dave")
	c.ok("E48 пространство не может проверять (и тем самым «выпускать») приглашения", st == 403, st)
	st, _ = k.do("POST", "/v1/actions/verify", "tok-cp", j(admPh.sign(t, k, map[string]any{"type": "account_delete", "user": "admin"}, nil)), nil)
	c.ok("E49 control-plane проверяет только приглашения, не другие действия", st == 403, st)
	t.Logf("регистрация устройств: %d/%d", c.n, c.n+c.f)
}
