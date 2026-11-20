package keyguard

// Атаки на аттестацию устройств. Цепочки строятся в тесте со своим корнем (настоящих ключей Google и Apple у нас нет):
// так проверяется каждое условие отказа. Разбор сверяется с настоящей цепочкой Google из testdata/attest.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------- построение цепочек ----------------

type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T, name string, parent *testCA, isCA bool, now time.Time) *testCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	signer, issuer := k, tpl
	if parent != nil {
		signer, issuer = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, issuer, &k.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{k, c}
}

func (ca *testCA) leaf(t *testing.T, pub *ecdsa.PublicKey, now time.Time, exts ...pkix.Extension) *x509.Certificate {
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: time.Unix(0, 0), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: exts}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func chainB64(certs ...*x509.Certificate) (out []string) {
	for _, c := range certs {
		out = append(out, base64.StdEncoding.EncodeToString(c.Raw))
	}
	return out
}

func mustDER(t *testing.T, v any, params ...string) []byte {
	b, err := asn1.MarshalWithParams(v, strings.Join(params, ","))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func explicit(t *testing.T, tag int, inner []byte) []byte {
	return mustDER(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner})
}

// keyParams — что «чип» записал об одном ключе.
type keyParams struct {
	challenge       []byte
	level           int
	purposes        []int
	origin          int
	locked          bool
	bootState       int
	noAuth          bool
	userAuth        bool
	packages        []string
	digest          []byte
	curve           int
	appIDInHardware bool
}

func goodKey(challenge []byte, digest []byte) keyParams {
	return keyParams{challenge: challenge, level: 2, purposes: []int{2}, origin: 0, locked: true, bootState: 0, noAuth: true,
		packages: []string{"kz.fugudeck.app"}, digest: digest, curve: 1}
}

func (p keyParams) extension(t *testing.T) pkix.Extension {
	var hw []byte
	hw = append(hw, explicit(t, tagPurpose, mustDER(t, p.purposes, "set"))...)
	hw = append(hw, explicit(t, tagAlgorithm, mustDER(t, 3))...)
	hw = append(hw, explicit(t, tagECCurve, mustDER(t, p.curve))...)
	if p.noAuth {
		hw = append(hw, explicit(t, tagNoAuthRequired, mustDER(t, asn1.NullRawValue))...)
	}
	if p.userAuth {
		hw = append(hw, explicit(t, tagUserAuthType, mustDER(t, 2))...)
	}
	hw = append(hw, explicit(t, tagOrigin, mustDER(t, p.origin))...)
	hw = append(hw, explicit(t, tagRootOfTrust, mustDER(t, rootOfTrust{VerifiedBootKey: make([]byte, 32), DeviceLocked: p.locked,
		VerifiedBootState: asn1.Enumerated(p.bootState), VerifiedBootHash: make([]byte, 32)}))...)
	type pkg struct {
		Name    []byte
		Version *big.Int
	}
	var pkgs []pkg
	for _, n := range p.packages {
		pkgs = append(pkgs, pkg{[]byte(n), big.NewInt(42)})
	}
	appID := explicit(t, tagAppID, mustDER(t, mustDER(t, struct {
		Packages []pkg    `asn1:"set"`
		Digests  [][]byte `asn1:"set"`
	}{pkgs, [][]byte{p.digest}})))
	var sw []byte
	if p.appIDInHardware {
		hw = append(hw, appID...)
	} else {
		sw = appID
	}
	seq := func(b []byte) asn1.RawValue {
		return asn1.RawValue{FullBytes: mustDER(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: b})}
	}
	return pkix.Extension{Id: oidKeyAttestation, Value: mustDER(t, keyDescription{AttestationVersion: 300, AttestationSecurityLevel: asn1.Enumerated(p.level),
		KeyMintVersion: 300, KeyMintSecurityLevel: asn1.Enumerated(p.level), AttestationChallenge: p.challenge, UniqueID: []byte{},
		SoftwareEnforced: seq(sw), HardwareEnforced: seq(hw)})}
}

// cbor — кодировщик для теста: карты (в порядке ключей аргумента), массивы, строки, байты.
func cborEnc(v any) []byte {
	head := func(major byte, n int) []byte {
		switch {
		case n < 24:
			return []byte{major<<5 | byte(n)}
		case n < 256:
			return []byte{major<<5 | 24, byte(n)}
		default:
			return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
		}
	}
	switch x := v.(type) {
	case string:
		return append(head(3, len(x)), x...)
	case []byte:
		return append(head(2, len(x)), x...)
	case []any:
		out := head(4, len(x))
		for _, e := range x {
			out = append(out, cborEnc(e)...)
		}
		return out
	case [][2]any:
		out := head(5, len(x))
		for _, kv := range x {
			out = append(append(out, cborEnc(kv[0])...), cborEnc(kv[1])...)
		}
		return out
	}
	panic("cborEnc")
}

type appleParams struct {
	appID   string
	counter uint32
	aaguid  string
	hash    []byte // clientDataHash, под который выпущена аттестация
}

// appleAttestation — объект App Attest, как его отдаёт DCAppAttestService, подписанный тестовым «корнем Apple».
func appleAttestation(t *testing.T, root *testCA, p appleParams, now time.Time) *appleIn {
	inter := newTestCA(t, "Apple App Attestation CA 1", root, true, now)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point, _ := pubBytes(&k.PublicKey)
	keyID := sha256.Sum256(point)
	app := sha256.Sum256([]byte(p.appID))
	authData := append([]byte{}, app[:]...)
	authData = append(authData, 0x40)
	authData = binary.BigEndian.AppendUint32(authData, p.counter)
	authData = append(authData, p.aaguid...)
	authData = binary.BigEndian.AppendUint16(authData, 32)
	authData = append(authData, keyID[:]...)
	nonce := sha256.Sum256(append(append([]byte{}, authData...), p.hash...))
	ext := pkix.Extension{Id: oidAppleNonce, Value: mustDER(t, struct {
		Nonce []byte `asn1:"explicit,tag:1"`
	}{nonce[:]})}
	cred := inter.leaf(t, &k.PublicKey, now, ext)
	obj := cborEnc([][2]any{{"fmt", "apple-appattest"},
		{"attStmt", [][2]any{{"x5c", []any{cred.Raw, inter.cert.Raw}}, {"receipt", []byte("r")}}}, {"authData", authData}})
	return &appleIn{Format: "apple-app-attest", KeyID: base64.StdEncoding.EncodeToString(keyID[:]), Attestation: base64.StdEncoding.EncodeToString(obj)}
}

const prodAAGUID = "appattest\x00\x00\x00\x00\x00\x00\x00"

// ---------------- тесты ----------------

func TestAttack_Attestation(t *testing.T) {
	c := &check{t: t}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	root := newTestCA(t, "тестовый корень", nil, true, now)
	inter := newTestCA(t, "тестовый УЦ чипа", root, true, now)
	evilRoot := newTestCA(t, "чужой корень", nil, true, now)
	digest := sha256.Sum256([]byte("сертификат подписи приложения"))

	pol := NewAttestPolicy("required")
	pol.AndroidRoots = x509.NewCertPool()
	pol.AndroidRoots.AddCert(root.cert)
	pol.AppleRoots = x509.NewCertPool()
	pol.AppleRoots.AddCert(root.cert)
	pol.AndroidPackage, pol.AndroidCertDigests, pol.AppleAppID = "kz.fugudeck.app", [][]byte{digest[:]}, "TEAM123456.kz.fugudeck.app"

	d := mkDev()
	sj, cj := ecJWK(&d.sess.PublicKey).Thumbprint(), ecJWK(&d.conf.PublicKey).Thumbprint()
	ch := pol.NewChallenge(now)

	// android — строит аттестацию из двух описаний ключей; mut меняет цепочки после сборки
	android := func(s, cf keyParams, signer *testCA, mut func(a *attestationIn)) error {
		a := &attestationIn{
			Session: &androidKeyIn{Format: "android-key", Chain: chainB64(signer.leaf(t, &d.sess.PublicKey, now, s.extension(t)), signer.cert, root.cert)},
			Confirm: &androidKeyIn{Format: "android-key", Chain: chainB64(signer.leaf(t, &d.conf.PublicKey, now, cf.extension(t)), signer.cert, root.cert)}}
		if mut != nil {
			mut(a)
		}
		raw, _ := json.Marshal(a)
		_, err := pol.Verify(raw, &d.sess.PublicKey, &d.conf.PublicKey, sj, cj, ch, now)
		return err
	}
	sess := goodKey(ch, digest[:])
	conf := goodKey(ch, digest[:])
	conf.noAuth, conf.userAuth = false, true // ключ подтверждения требует биометрию
	denied := func(name string, err error, want string) {
		c.ok(name, err != nil && strings.Contains(err.Error(), want), err)
	}
	with := func(base keyParams, f func(*keyParams)) keyParams { f(&base); return base }

	raw, _ := json.Marshal(&attestationIn{
		Session: &androidKeyIn{Format: "android-key", Chain: chainB64(inter.leaf(t, &d.sess.PublicKey, now, sess.extension(t)), inter.cert, root.cert)},
		Confirm: &androidKeyIn{Format: "android-key", Chain: chainB64(inter.leaf(t, &d.conf.PublicKey, now, conf.extension(t)), inter.cert, root.cert)}})
	res, err := pol.Verify(raw, &d.sess.PublicKey, &d.conf.PublicKey, sj, cj, ch, now)
	c.ok("T1 Android: оба ключа в StrongBox, наше приложение, загрузчик закрыт — принято", err == nil && res.String() == "android-key/strongbox", res, err)
	res, err = func() (*AttestResult, error) {
		tee := with(sess, func(k *keyParams) { k.level = 1 })
		raw, _ := json.Marshal(&attestationIn{
			Session: &androidKeyIn{Format: "android-key", Chain: chainB64(inter.leaf(t, &d.sess.PublicKey, now, tee.extension(t)), inter.cert, root.cert)},
			Confirm: &androidKeyIn{Format: "android-key", Chain: chainB64(inter.leaf(t, &d.conf.PublicKey, now, conf.extension(t)), inter.cert, root.cert)}})
		return pol.Verify(raw, &d.sess.PublicKey, &d.conf.PublicKey, sj, cj, ch, now)
	}()
	c.ok("T2 один ключ в TEE — уровень устройства по слабейшему", err == nil && res.Level == "tee", res, err)

	denied("T3 программный ключ (эмулятор) отклонён", android(with(sess, func(k *keyParams) { k.level = 0 }), conf, inter, nil), "программные")
	denied("T4 чужой вызов (аттестация для другой регистрации) отклонён", android(with(sess, func(k *keyParams) { k.challenge = pol.NewChallenge(now) }), conf, inter, nil), "вызов не совпадает")
	denied("T5 цепочка от чужого корня отклонена", android(sess, conf, newTestCA(t, "УЦ злоумышленника", evilRoot, true, now), nil), "не ведёт к корню")
	denied("T6 сертификат на другой ключ отклонён", android(sess, conf, inter, func(a *attestationIn) { a.Session, a.Confirm = a.Confirm, a.Session }), "другой ключ")
	denied("T7 разблокированный загрузчик отклонён", android(with(sess, func(k *keyParams) { k.locked = false }), conf, inter, nil), "загрузчик")
	denied("T8 изменённая система (verified boot ≠ Verified) отклонена", android(with(sess, func(k *keyParams) { k.bootState = 2 }), conf, inter, nil), "загрузчик")
	denied("T9 другое приложение (чужой пакет) отклонено", android(with(sess, func(k *keyParams) { k.packages = []string{"com.evil.app"} }), conf, inter, nil), "другим приложением")
	denied("T10 общий UID с другим пакетом отклонён", android(with(sess, func(k *keyParams) { k.packages = []string{"kz.fugudeck.app", "com.evil.app"} }), conf, inter, nil), "другим приложением")
	denied("T11 пересобранное приложение (чужая подпись) отклонено", android(with(sess, func(k *keyParams) { k.digest = make([]byte, 32) }), conf, inter, nil), "чужим ключом")
	denied("T12 импортированный ключ (не создан в чипе) отклонён", android(with(sess, func(k *keyParams) { k.origin = 2 }), conf, inter, nil), "импортирован")
	denied("T13 ключ, годный для расшифровки, отклонён", android(with(sess, func(k *keyParams) { k.purposes = []int{2, 1} }), conf, inter, nil), "не только для подписи")
	denied("T14 ключ подтверждения без биометрии отклонён", android(sess, with(conf, func(k *keyParams) { k.noAuth, k.userAuth = true, false }), inter, nil), "биометрии")
	denied("T15 только одна цепочка из двух — отклонено", android(sess, conf, inter, func(a *attestationIn) { a.Confirm = nil }), "обоих ключей")
	denied("T16 кривая не P-256 отклонена", android(with(sess, func(k *keyParams) { k.curve = 2 }), conf, inter, nil), "P-256")

	// «Дочерний» сертификат: аттестованный ключ телефона (не УЦ) подписывает сертификат с выдуманным описанием.
	phoneKey := newTestCA(t, "Android Keystore Key", inter, false, now)
	denied("T17 сертификат, выпущенный ключом телефона (не УЦ), отклонён", android(sess, conf, phoneKey, func(a *attestationIn) {
		for _, k := range []*androidKeyIn{a.Session, a.Confirm} {
			k.Chain = append(k.Chain[:2], append(chainB64(inter.cert), k.Chain[2:]...)...)
		}
	}), "не ведёт к корню")
	denied("T18 просроченная цепочка отклонена", func() error {
		raw, _ := json.Marshal(&attestationIn{
			Session: &androidKeyIn{Format: "android-key", Chain: chainB64(inter.leaf(t, &d.sess.PublicKey, now, sess.extension(t)), inter.cert, root.cert)},
			Confirm: &androidKeyIn{Format: "android-key", Chain: chainB64(inter.leaf(t, &d.conf.PublicKey, now, conf.extension(t)), inter.cert, root.cert)}})
		_, err := pol.Verify(raw, &d.sess.PublicKey, &d.conf.PublicKey, sj, cj, ch, now.Add(48*time.Hour))
		return err
	}(), "не ведёт к корню")

	_, err = pol.Verify(nil, &d.sess.PublicKey, &d.conf.PublicKey, sj, cj, nil, now)
	denied("T19 режим required: без аттестации — отказ", err, "не прислало")
	opt := *pol
	opt.Mode = "optional"
	res, err = opt.Verify([]byte("null"), &d.sess.PublicKey, &d.conf.PublicKey, sj, cj, nil, now)
	c.ok("T20 режим optional: без аттестации — регистрация без отметки", err == nil && res == nil, res, err)
	bare := *pol
	bare.AndroidPackage = ""
	_, err = bare.Verify(raw, &d.sess.PublicKey, &d.conf.PublicKey, sj, cj, ch, now)
	denied("T21 платформа не настроена на сервере — её аттестация не принимается", err, "не настроена")

	// ---- вызов ----
	_, err = pol.checkChallenge(ch, now.Add(14*time.Minute))
	_, err2 := pol.checkChallenge(ch, now.Add(16*time.Minute))
	c.ok("T22 вызов живёт 15 минут", err == nil && err2 != nil, err, err2)
	_, err = NewAttestPolicy("required").checkChallenge(ch, now)
	forged := append([]byte{}, ch...)
	forged[20] ^= 1 // время выдачи
	_, err2 = pol.checkChallenge(forged, now)
	c.ok("T23 вызов другого процесса и вызов с подправленным временем отклонены", err != nil && err2 != nil, err, err2)

	// ---- Apple App Attest ----
	hash := sha256.Sum256(append(append([]byte{}, ch...), []byte(sj+"."+cj)...))
	apple := func(p appleParams, signer *testCA, mut func(*appleIn)) (*AttestResult, error) {
		in := appleAttestation(t, signer, p, now)
		if mut != nil {
			mut(in)
		}
		raw, _ := json.Marshal(&attestationIn{App: in})
		return pol.Verify(raw, &d.sess.PublicKey, &d.conf.PublicKey, sj, cj, ch, now)
	}
	good := appleParams{appID: pol.AppleAppID, aaguid: prodAAGUID, hash: hash[:]}
	res, err = apple(good, root, nil)
	c.ok("I1 iOS: App Attest нашего приложения на этот вызов и эти ключи — принято", err == nil && res.String() == "apple-app-attest/app-attest", res, err)
	_, err = apple(appleParams{appID: pol.AppleAppID, aaguid: prodAAGUID, hash: make([]byte, 32)}, root, nil)
	denied("I2 аттестация на другой вызов или другие ключи устройства отклонена", err, "nonce")
	_, err = apple(with2(good, func(p *appleParams) { p.appID = "EVIL000000.com.evil" }), root, nil)
	denied("I3 другое приложение отклонено", err, "другое приложение")
	_, err = apple(with2(good, func(p *appleParams) { p.aaguid = "appattestdevelop" }), root, nil)
	denied("I4 среда разработки App Attest отклонена", err, "не боевая")
	_, err = apple(with2(good, func(p *appleParams) { p.counter = 3 }), root, nil)
	denied("I5 уже использованный ключ App Attest отклонён", err, "уже использовался")
	_, err = apple(good, evilRoot, nil)
	denied("I6 цепочка не от корня Apple отклонена", err, "не ведёт к корню")
	_, err = apple(good, root, func(in *appleIn) { in.KeyID = base64.StdEncoding.EncodeToString(make([]byte, 32)) })
	denied("I7 чужой идентификатор ключа отклонён", err, "идентификатор ключа")
	_, err = apple(good, root, func(in *appleIn) { in.Attestation = base64.StdEncoding.EncodeToString([]byte{0xa1, 0x7f}) })
	denied("I8 мусор вместо объекта аттестации отклонён без паники", err, "не разбирается")

	// ---- настоящая цепочка Google (устройство с разблокированным загрузчиком, системное приложение) ----
	realPEM, rerr := os.ReadFile("testdata/attest/android_ec_tee.certs")
	if rerr != nil {
		t.Fatal(rerr)
	}
	realChain := certsFromPEM(realPEM)
	der, _ := base64.StdEncoding.DecodeString(realChain[0])
	leaf, _ := x509.ParseCertificate(der)
	realPol := NewAttestPolicy("required") // вшитые корни Google
	realPol.AndroidPackage, realPol.AndroidCertDigests = "kz.fugudeck.app", [][]byte{digest[:]}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	_, err = realPol.androidKey(&androidKeyIn{Format: "android-key", Chain: realChain}, leaf.PublicKey.(*ecdsa.PublicKey), []byte("abc"), false, at)
	denied("G1 настоящая цепочка: дошла до вшитого корня Google, вызов и чип разобраны; отклонена за разблокированный загрузчик", err, "загрузчик")
	realPol.AllowUnlocked = true
	_, err = realPol.androidKey(&androidKeyIn{Format: "android-key", Chain: realChain}, leaf.PublicKey.(*ecdsa.PublicKey), []byte("abc"), false, at)
	denied("G2 она же при разрешённом загрузчике: отклонена как ключ другого приложения", err, "другим приложением")
	_, err = realPol.androidKey(&androidKeyIn{Format: "android-key", Chain: realChain}, leaf.PublicKey.(*ecdsa.PublicKey), []byte("abd"), false, at)
	denied("G3 она же с другим вызовом — отклонена по вызову", err, "вызов не совпадает")
	sbPEM, _ := os.ReadFile("testdata/attest/android_ec_strongbox.certs")
	sb := certsFromPEM(sbPEM)
	der, _ = base64.StdEncoding.DecodeString(sb[0])
	leaf, _ = x509.ParseCertificate(der)
	_, err = realPol.androidKey(&androidKeyIn{Format: "android-key", Chain: sb}, leaf.PublicKey.(*ecdsa.PublicKey), []byte("abc"), false, at)
	denied("G4 образец с неверной подписью в цепочке и не-Google корнем отклонён", err, "не ведёт к корню")
	t.Logf("аттестация: %d/%d", c.n, c.n+c.f)
}

func with2(p appleParams, f func(*appleParams)) appleParams { f(&p); return p }

// Через настоящий обработчик регистрации: вызов → регистрация с аттестацией → повтор.
func TestAttack_AttestationEnroll(t *testing.T) {
	k := newRig(t)
	k.srv.Verifier.Devices = NewDevices()
	p := newIdP(t, k.now)
	k.srv.Enroll = &EnrollConfig{Issuer: p.iss, JWKSURL: p.srv.URL, ClientID: "deck-app", EnrollURL: enrollURL, StatusURL: statusURL,
		Admins: []string{"admin"}, HTTP: http.DefaultClient}
	c := &check{t: t}
	now := k.now()
	root := newTestCA(t, "тестовый корень", nil, true, now)
	inter := newTestCA(t, "тестовый УЦ чипа", root, true, now)
	digest := sha256.Sum256([]byte("подпись"))
	pol := NewAttestPolicy("required")
	pol.AndroidRoots = x509.NewCertPool()
	pol.AndroidRoots.AddCert(root.cert)
	pol.AndroidPackage, pol.AndroidCertDigests = "kz.fugudeck.app", [][]byte{digest[:]}
	k.srv.Attest = pol

	challenge := func() (string, []byte) {
		st, body := k.do("POST", "/v1/devices/challenge", "tok-cp", nil, nil)
		var m struct{ Challenge string }
		json.Unmarshal([]byte(body), &m)
		raw, _ := b64u.DecodeString(m.Challenge)
		if st != 200 || len(raw) != 40 {
			t.Fatalf("вызов: %d %s", st, body)
		}
		return m.Challenge, raw
	}
	attest := func(d newDev, ch []byte) *attestationIn {
		s := goodKey(ch, digest[:])
		cf := goodKey(ch, digest[:])
		cf.noAuth, cf.userAuth = false, true
		return &attestationIn{
			Session: &androidKeyIn{Format: "android-key", Chain: chainB64(inter.leaf(t, &d.sess.PublicKey, now, s.extension(t)), inter.cert, root.cert)},
			Confirm: &androidKeyIn{Format: "android-key", Chain: chainB64(inter.leaf(t, &d.conf.PublicKey, now, cf.extension(t)), inter.cert, root.cert)}}
	}
	enroll := func(d newDev, user string, att *attestationIn, ch, storage string) (int, string) {
		tok := p.token(user, ecJWK(&d.sess.PublicKey).Thumbprint(), nil)
		body := map[string]any{"access_token": tok, "dpop": d.proof(tok, now, nil), "session_jwk": ecJWK(&d.sess.PublicKey),
			"confirm_jwk": ecJWK(&d.conf.PublicKey), "enroll": d.enrollAction(now, nil, nil), "key_storage": storage, "csr": csrFor(d.sess)}
		if att != nil {
			body["attestation"], body["challenge"] = att, ch
		}
		return k.do("POST", "/v1/devices", "tok-cp", j(body), nil)
	}

	st, _ := k.do("POST", "/v1/devices/challenge", "tok-anna", nil, nil)
	c.ok("A1 вызов выдаётся только control-plane", st == 403, st)
	anna := mkDev()
	chS, ch := challenge()
	att := attest(anna, ch)
	st, body := enroll(anna, "anna", att, chS, "software")
	id := DeviceIDFor(ecJWK(&anna.conf.PublicKey).Thumbprint())
	dv, _ := k.srv.Verifier.Devices.Get(id)
	c.ok("A2 регистрация с аттестацией: отметка в реестре; место хранения — из аттестации, а не со слов приложения",
		st == 200 && dv != nil && dv.Attested == "android-key/strongbox" && dv.KeyStorage == "strongbox" && strings.Contains(body, `"attested":"android-key/strongbox"`), st, body)

	st, body = enroll(mkDev(), "bob", nil, "", "strongbox")
	c.ok("A3 режим required: без аттестации устройство не регистрируется", st == 403 && strings.Contains(body, "аттестация"), st, body)

	// та же аттестация и тот же вызов для ДРУГОЙ регистрации тех же ключей: вызов одноразовый
	k.srv.Verifier.Devices = NewDevices()
	st, body = enroll(anna, "anna", att, chS, "")
	c.ok("A4 повтор вызова отклонён (аттестацию нельзя предъявить дважды)", st == 403 && strings.Contains(body, "уже использован"), st, body)

	bob := mkDev()
	chS2, ch2 := challenge()
	st, body = enroll(bob, "bob", attest(anna, ch2), chS2, "")
	c.ok("A5 аттестация чужих ключей к своей регистрации не подходит", st == 403 && strings.Contains(body, "другой ключ"), st, body)
	st, _ = enroll(bob, "bob", attest(bob, ch2), chS2, "")
	c.ok("A6 неудачная попытка не сожгла вызов: с верной аттестацией он принимается", st == 200, st)

	carl := mkDev()
	st, body = enroll(carl, "carl", attest(carl, []byte("самодельный вызов")), b64u.EncodeToString([]byte("самодельный вызов")), "")
	c.ok("A7 самодельный вызов (не от сервера) отклонён", st == 403 && strings.Contains(body, "не от этого сервера"), st, body)
	c.ok("A8 отказы попали в журнал", strings.Contains(k.logs.String(), "event=device.attestation_rejected"))
	t.Logf("аттестация при регистрации: %d/%d", c.n, c.n+c.f)
}
