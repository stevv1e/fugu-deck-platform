package keyguard

// Проверка аттестации устройства при регистрации (ARCHITECTURE-v2.md, 3.3): доказательство, что ключи созданы в чипе
// настоящего телефона настоящим приложением, а не скриптом на ноутбуке.
//
//   Android — Key Attestation: у КАЖДОГО из двух ключей (сессии и подтверждения) своя цепочка сертификатов до корня
//     Google. В листе — расширение KeyDescription: вызов сервера, уровень защиты (TEE/StrongBox), состояние загрузчика,
//     пакет и подпись приложения, требование биометрии.
//   iOS — App Attest: один объект на установку приложения, цепочка до корня Apple. Ключи устройства привязаны к нему
//     через clientDataHash = SHA-256(вызов ‖ "jkt сессии.jkt подтверждения"). Сам Secure Enclave цепочку на свои ключи
//     не выдаёт: App Attest подтверждает приложение и телефон, а не место хранения каждого ключа.
//
// Вызов выдаёт keyguard (POST /v1/devices/challenge), он одноразовый и живёт 15 минут: чужую или старую аттестацию
// не подставить. Корни доверия — файлы roots/*.certs, вшитые в бинарник.
//
// Отзыв скомпрометированных ключей аттестации (список Google) здесь НЕ проверяется — нужен выход в интернет из
// keyguard; см. README, «НЕ готово для боя».

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

//go:embed roots/android.certs
var androidRootsPEM []byte

//go:embed roots/apple.certs
var appleRootPEM []byte

const ChallengeTTL = 15 * time.Minute

var (
	oidKeyAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
	oidAppleNonce     = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
	ErrAttestation    = errors.New("аттестация устройства не принята")
)

// AttestPolicy — что требовать от аттестации. Платформа без настроек (пакет/подпись, AppID) не принимается вовсе:
// без них аттестацию выдало бы любое приложение на телефоне.
type AttestPolicy struct {
	// "off" — не смотреть; "optional" — проверять, если прислана; "required" — без неё не регистрировать;
	// "vouched" — проверять, если прислана; устройство без неё ждёт подтверждения аттестованным устройством (Vouched)
	Mode string

	AndroidRoots       *x509.CertPool
	AndroidPackage     string   // applicationId приложения
	AndroidCertDigests [][]byte // SHA-256 сертификатов подписи приложения (любой из них)
	AllowUnlocked      bool     // принимать разблокированный загрузчик (только стенды)

	AppleRoots       *x509.CertPool
	AppleAppID       string // "<TeamID>.<bundle id>"
	AllowDevelopment bool   // принимать среду разработки App Attest (aaguid "appattestdevelop")

	key []byte // ключ HMAC вызовов; случайный на процесс — перезапуск гасит выданные вызовы
}

// NeedsVoucher — устройство без аттестации (attested — его Device.Attested) можно активировать только подписью
// устройства, которое само прошло аттестацию: иначе скрипт на ноутбуке подтвердил бы такой же скрипт.
func (p *AttestPolicy) NeedsVoucher(attested string) bool {
	return p != nil && p.Mode == "vouched" && attested == ""
}

// AttestResult — что удалось подтвердить. Попадает в реестр устройств и в журнал.
type AttestResult struct {
	Format string // "android-key" | "apple-app-attest"
	Level  string // android: "strongbox" | "tee" (слабейший из двух ключей); ios: "app-attest"
}

func (r *AttestResult) String() string {
	if r == nil {
		return ""
	}
	return r.Format + "/" + r.Level
}

func poolFromPEM(b []byte) *x509.CertPool {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		panic("keyguard: вшитые корни аттестации не разбираются")
	}
	return p
}

// NewAttestPolicy — политика с вшитыми корнями Google и Apple.
func NewAttestPolicy(mode string) *AttestPolicy {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return &AttestPolicy{Mode: mode, AndroidRoots: poolFromPEM(androidRootsPEM), AppleRoots: poolFromPEM(appleRootPEM), key: k}
}

// ---------------- вызов ----------------

// NewChallenge: 16 случайных байт ‖ время выдачи (8) ‖ HMAC (16). Состояния не требует; одноразовость — через Nonces.
func (p *AttestPolicy) NewChallenge(now time.Time) []byte {
	c := make([]byte, 24, 40)
	rand.Read(c[:16])
	binary.BigEndian.PutUint64(c[16:], uint64(now.Unix()))
	m := hmac.New(sha256.New, p.key)
	m.Write(c)
	return append(c, m.Sum(nil)[:16]...)
}

// checkChallenge — выдан этим процессом и не старше ChallengeTTL; возвращает момент истечения.
func (p *AttestPolicy) checkChallenge(c []byte, now time.Time) (time.Time, error) {
	if len(c) != 40 {
		return time.Time{}, fmt.Errorf("%w: вызов не от этого сервера", ErrAttestation)
	}
	m := hmac.New(sha256.New, p.key)
	m.Write(c[:24])
	if !hmac.Equal(m.Sum(nil)[:16], c[24:]) {
		return time.Time{}, fmt.Errorf("%w: вызов не от этого сервера (или сервер перезапускался)", ErrAttestation)
	}
	at := time.Unix(int64(binary.BigEndian.Uint64(c[16:24])), 0)
	if now.Sub(at) > ChallengeTTL || at.Sub(now) > MaxFuture {
		return time.Time{}, fmt.Errorf("%w: вызов устарел", ErrAttestation)
	}
	return at.Add(ChallengeTTL), nil
}

// ---------------- общий вход ----------------

type attestationIn struct {
	Session *androidKeyIn `json:"session"`
	Confirm *androidKeyIn `json:"confirm"`
	App     *appleIn      `json:"app"`
}

type androidKeyIn struct {
	Format string   `json:"format"`
	Chain  []string `json:"chain"`
}

type appleIn struct {
	Format      string `json:"format"`
	KeyID       string `json:"keyId"`
	Attestation string `json:"attestation"`
}

// Verify проверяет аттестацию для пары ключей устройства. challenge уже проверен checkChallenge.
// nil, nil — аттестации нет и режим её не требует.
func (p *AttestPolicy) Verify(raw json.RawMessage, session, confirm *ecdsa.PublicKey, sessJKT, confJKT string, challenge []byte, now time.Time) (*AttestResult, error) {
	var in attestationIn
	if len(bytes.TrimSpace(raw)) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("%w: не разбирается", ErrAttestation)
		}
	}
	switch {
	case in.Session != nil || in.Confirm != nil:
		if in.Session == nil || in.Confirm == nil {
			return nil, fmt.Errorf("%w: нужны цепочки обоих ключей", ErrAttestation)
		}
		if p.AndroidPackage == "" || len(p.AndroidCertDigests) == 0 {
			return nil, fmt.Errorf("%w: аттестация Android не настроена на сервере", ErrAttestation)
		}
		ls, err := p.androidKey(in.Session, session, challenge, false, now)
		if err != nil {
			return nil, fmt.Errorf("%w: ключ сессии: %v", ErrAttestation, err)
		}
		lc, err := p.androidKey(in.Confirm, confirm, challenge, true, now)
		if err != nil {
			return nil, fmt.Errorf("%w: ключ подтверждения: %v", ErrAttestation, err)
		}
		level := "strongbox"
		if ls != 2 || lc != 2 {
			level = "tee"
		}
		return &AttestResult{Format: "android-key", Level: level}, nil
	case in.App != nil:
		if p.AppleAppID == "" {
			return nil, fmt.Errorf("%w: аттестация iOS не настроена на сервере", ErrAttestation)
		}
		h := sha256.Sum256(append(append([]byte{}, challenge...), []byte(sessJKT+"."+confJKT)...))
		if err := p.appleApp(in.App, h[:], now); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAttestation, err)
		}
		return &AttestResult{Format: "apple-app-attest", Level: "app-attest"}, nil
	}
	if p.Mode == "required" {
		return nil, fmt.Errorf("%w: устройство её не прислало (нужен телефон с ключами в чипе, не эмулятор)", ErrAttestation)
	}
	return nil, nil
}

func parseChain(b64 []string) ([]*x509.Certificate, error) {
	if len(b64) < 2 || len(b64) > 8 {
		return nil, errors.New("в цепочке должно быть от 2 до 8 сертификатов")
	}
	var out []*x509.Certificate
	for _, s := range b64 {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, errors.New("base64 в цепочке")
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("сертификат цепочки не разбирается")
		}
		out = append(out, c)
	}
	return out, nil
}

// verifyChain — лист подписан цепочкой до одного из корней. Проверку путей делает crypto/x509: промежуточные обязаны
// быть УЦ, поэтому «дочерний» сертификат, выпущенный аттестованным ключом телефона, цепочку не продолжит.
func verifyChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) error {
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("цепочка не ведёт к корню доверия: %v", err)
	}
	return nil
}

// ---------------- Android Key Attestation ----------------

type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int
	KeyMintSecurityLevel     asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	HardwareEnforced         asn1.RawValue
}

type rootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

// Теги AuthorizationList (KeyMint): значение каждого — EXPLICIT [tag].
const (
	tagPurpose        = 1
	tagAlgorithm      = 2
	tagECCurve        = 10
	tagNoAuthRequired = 503
	tagUserAuthType   = 504
	tagOrigin         = 702
	tagRootOfTrust    = 704
	tagAppID          = 709
)

// authList разбирает AuthorizationList в карту тег → содержимое EXPLICIT-обёртки.
func authList(seq asn1.RawValue) (map[int][]byte, error) {
	out := map[int][]byte{}
	rest := seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &v); err != nil {
			return nil, errors.New("AuthorizationList не разбирается")
		}
		if v.Class != asn1.ClassContextSpecific {
			return nil, errors.New("AuthorizationList: неожиданный элемент")
		}
		if _, dup := out[v.Tag]; dup {
			return nil, errors.New("AuthorizationList: повтор тега")
		}
		out[v.Tag] = v.Bytes
	}
	return out, nil
}

func asnInt(b []byte) (int, bool) {
	var x int
	rest, err := asn1.Unmarshal(b, &x)
	return x, err == nil && len(rest) == 0
}

// androidKey проверяет цепочку одного ключа; возвращает уровень защиты (1 — TEE, 2 — StrongBox).
func (p *AttestPolicy) androidKey(in *androidKeyIn, pub *ecdsa.PublicKey, challenge []byte, needUserAuth bool, now time.Time) (int, error) {
	if in.Format != "android-key" {
		return 0, errors.New("неизвестный формат")
	}
	chain, err := parseChain(in.Chain)
	if err != nil {
		return 0, err
	}
	if err := verifyChain(chain, p.AndroidRoots, now); err != nil {
		return 0, err
	}
	if lp, ok := chain[0].PublicKey.(*ecdsa.PublicKey); !ok || !lp.Equal(pub) {
		return 0, errors.New("сертификат выдан на другой ключ")
	}
	// Расширение берётся только из листа; у остальных его быть не должно (иначе в цепочку «вложили» чужое описание).
	var ext []byte
	for i, c := range chain {
		for _, e := range c.Extensions {
			if e.Id.Equal(oidKeyAttestation) {
				if i != 0 || ext != nil {
					return 0, errors.New("описание ключа не в листе цепочки или повторяется")
				}
				ext = e.Value
			}
		}
	}
	if ext == nil {
		return 0, errors.New("в сертификате нет описания ключа (это не аттестация)")
	}
	var kd keyDescription
	if rest, err := asn1.Unmarshal(ext, &kd); err != nil || len(rest) != 0 {
		return 0, errors.New("описание ключа не разбирается")
	}
	if !bytes.Equal(kd.AttestationChallenge, challenge) {
		return 0, errors.New("вызов не совпадает (аттестация создана не для этой регистрации)")
	}
	level := int(kd.KeyMintSecurityLevel)
	if (level != 1 && level != 2) || (kd.AttestationSecurityLevel != 1 && kd.AttestationSecurityLevel != 2) {
		return 0, errors.New("ключ или аттестация — программные, не в чипе")
	}
	hw, err := authList(kd.HardwareEnforced)
	if err != nil {
		return 0, err
	}
	sw, err := authList(kd.SoftwareEnforced)
	if err != nil {
		return 0, err
	}
	// Свойства ключа читаются ТОЛЬКО из списка, который гарантирует чип: программному списку верить нельзя.
	if alg, ok := asnInt(hw[tagAlgorithm]); !ok || alg != 3 {
		return 0, errors.New("ключ не EC")
	}
	if curve, ok := asnInt(hw[tagECCurve]); !ok || curve != 1 {
		return 0, errors.New("кривая не P-256")
	}
	if origin, ok := asnInt(hw[tagOrigin]); !ok || origin != 0 {
		return 0, errors.New("ключ не создан в чипе (импортирован)")
	}
	var purposes []int
	if _, err := asn1.UnmarshalWithParams(hw[tagPurpose], &purposes, "set"); err != nil || !contains2(purposes, 2) {
		return 0, errors.New("ключ не для подписи")
	}
	for _, x := range purposes { // 2 — подпись, 3 — проверка; шифрование, обёртка ключей, согласование — нельзя
		if x != 2 && x != 3 {
			return 0, errors.New("ключ годится не только для подписи")
		}
	}
	var rot rootOfTrust
	if rest, err := asn1.Unmarshal(hw[tagRootOfTrust], &rot); err != nil || len(rest) != 0 {
		return 0, errors.New("нет сведений о загрузчике")
	}
	if !p.AllowUnlocked && (!rot.DeviceLocked || rot.VerifiedBootState != 0) {
		return 0, errors.New("загрузчик разблокирован или система изменена")
	}
	_, noAuth := hw[tagNoAuthRequired]
	_, authType := hw[tagUserAuthType]
	if needUserAuth && (noAuth || !authType) {
		return 0, errors.New("ключ подтверждения не требует биометрии")
	}
	// Пакет и подпись приложения записывает система (программный список), но под той же подписью чипа.
	appID, ok := sw[tagAppID]
	if !ok {
		appID, ok = hw[tagAppID]
	}
	if !ok {
		return 0, errors.New("нет сведений о приложении")
	}
	if err := p.checkAndroidApp(appID); err != nil {
		return 0, err
	}
	return level, nil
}

func (p *AttestPolicy) checkAndroidApp(wrapped []byte) error {
	var octets []byte
	if rest, err := asn1.Unmarshal(wrapped, &octets); err != nil || len(rest) != 0 {
		return errors.New("сведения о приложении не разбираются")
	}
	var id struct {
		Packages []struct {
			Name    []byte
			Version *big.Int
		} `asn1:"set"`
		Digests [][]byte `asn1:"set"`
	}
	if rest, err := asn1.Unmarshal(octets, &id); err != nil || len(rest) != 0 {
		return errors.New("сведения о приложении не разбираются")
	}
	// Общий UID делят несколько пакетов — тогда ключ доступен им всем. Принимаем только единственный наш пакет.
	if len(id.Packages) != 1 || string(id.Packages[0].Name) != p.AndroidPackage {
		return errors.New("ключ создан другим приложением")
	}
	for _, d := range id.Digests {
		for _, want := range p.AndroidCertDigests {
			if bytes.Equal(d, want) {
				return nil
			}
		}
	}
	return errors.New("приложение подписано чужим ключом (пересобранное)")
}

func contains2(a []int, x int) bool {
	for _, e := range a {
		if e == x {
			return true
		}
	}
	return false
}

// ---------------- Apple App Attest ----------------

func (p *AttestPolicy) appleApp(in *appleIn, clientDataHash []byte, now time.Time) error {
	if in.Format != "apple-app-attest" {
		return errors.New("неизвестный формат")
	}
	raw, err := base64.StdEncoding.DecodeString(in.Attestation)
	if err != nil {
		return errors.New("base64 аттестации")
	}
	keyID, err := base64.StdEncoding.DecodeString(in.KeyID)
	if err != nil || len(keyID) != 32 {
		return errors.New("идентификатор ключа App Attest")
	}
	v, rest, err := cborDecode(raw, 0)
	if err != nil || len(rest) != 0 {
		return errors.New("объект аттестации не разбирается")
	}
	obj, _ := v.(map[string]any)
	stmt, _ := obj["attStmt"].(map[string]any)
	authData, _ := obj["authData"].([]byte)
	x5c, _ := stmt["x5c"].([]any)
	if obj["fmt"] != "apple-appattest" || len(x5c) < 2 || len(x5c) > 8 || len(authData) < 55 {
		return errors.New("объект аттестации неполон")
	}
	var chain []*x509.Certificate
	for _, e := range x5c {
		der, _ := e.([]byte)
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return errors.New("сертификат цепочки не разбирается")
		}
		chain = append(chain, c)
	}
	if err := verifyChain(chain, p.AppleRoots, now); err != nil {
		return err
	}
	// nonce в сертификате = SHA-256(authData ‖ clientDataHash): привязывает аттестацию к вызову и ключам устройства
	want := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
	var got []byte
	for _, e := range chain[0].Extensions {
		if e.Id.Equal(oidAppleNonce) {
			var seq struct {
				Nonce []byte `asn1:"explicit,tag:1"`
			}
			if rest, err := asn1.Unmarshal(e.Value, &seq); err == nil && len(rest) == 0 {
				got = seq.Nonce
			}
		}
	}
	if !hmac.Equal(got, want[:]) {
		return errors.New("аттестация создана не для этой регистрации (nonce)")
	}
	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("ключ App Attest не EC")
	}
	point, err := pubBytes(pub)
	if err != nil {
		return errors.New("ключ App Attest")
	}
	if kh := sha256.Sum256(point); !bytes.Equal(kh[:], keyID) {
		return errors.New("идентификатор ключа не соответствует сертификату")
	}
	// authData: rpIdHash(32) ‖ flags(1) ‖ counter(4) ‖ aaguid(16) ‖ credIdLen(2) ‖ credId
	app := sha256.Sum256([]byte(p.AppleAppID))
	if !bytes.Equal(authData[:32], app[:]) {
		return errors.New("аттестацию выдало другое приложение")
	}
	if binary.BigEndian.Uint32(authData[33:37]) != 0 {
		return errors.New("ключ App Attest уже использовался")
	}
	aaguid := string(authData[37:53])
	prod := aaguid == "appattest"+strings.Repeat("\x00", 7)
	if !prod && !(p.AllowDevelopment && aaguid == "appattestdevelop") {
		return errors.New("среда App Attest не боевая")
	}
	n := int(binary.BigEndian.Uint16(authData[53:55]))
	if len(authData) < 55+n || !bytes.Equal(authData[55:55+n], keyID) {
		return errors.New("идентификатор ключа не соответствует данным аттестации")
	}
	return nil
}

// cborDecode — минимальный разбор CBOR (RFC 8949) для объекта App Attest: целые, строки байт и текста, массивы,
// карты с текстовыми ключами. Всё остальное (теги, числа с плавающей точкой, неопределённая длина) — ошибка.
func cborDecode(b []byte, depth int) (any, []byte, error) {
	bad := errors.New("cbor")
	if len(b) == 0 || depth > 8 {
		return nil, nil, bad
	}
	major, info := b[0]>>5, b[0]&0x1f
	b = b[1:]
	var n uint64
	switch {
	case info < 24:
		n = uint64(info)
	case info <= 27:
		size := 1 << (info - 24)
		if len(b) < size {
			return nil, nil, bad
		}
		for _, x := range b[:size] {
			n = n<<8 | uint64(x)
		}
		b = b[size:]
	default:
		return nil, nil, bad
	}
	switch major {
	case 0:
		return n, b, nil
	case 2, 3:
		if n > uint64(len(b)) {
			return nil, nil, bad
		}
		if major == 2 {
			return append([]byte{}, b[:n]...), b[n:], nil
		}
		return string(b[:n]), b[n:], nil
	case 4:
		if n > 64 {
			return nil, nil, bad
		}
		out := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			v, rest, err := cborDecode(b, depth+1)
			if err != nil {
				return nil, nil, err
			}
			out, b = append(out, v), rest
		}
		return out, b, nil
	case 5:
		if n > 64 {
			return nil, nil, bad
		}
		out := map[string]any{}
		for i := uint64(0); i < n; i++ {
			k, rest, err := cborDecode(b, depth+1)
			ks, ok := k.(string)
			if err != nil || !ok {
				return nil, nil, bad
			}
			if _, dup := out[ks]; dup {
				return nil, nil, bad
			}
			v, rest, err := cborDecode(rest, depth+1)
			if err != nil {
				return nil, nil, err
			}
			out[ks], b = v, rest
		}
		return out, b, nil
	}
	return nil, nil, bad
}

// certsFromPEM — для тестов и стендов: цепочка из PEM в том виде, как её шлёт приложение (base64 DER по порядку).
func certsFromPEM(b []byte) (out []string) {
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			return out
		}
		out = append(out, base64.StdEncoding.EncodeToString(blk.Bytes))
	}
}
