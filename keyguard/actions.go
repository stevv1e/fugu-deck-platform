package keyguard

// Подписанные действия (architecture.md 3.4): JWS над каноническим JSON {type, поля, space, device_id, nonce, ts}, ECDSA P-256
// ключом ПОДТВЕРЖДЕНИЯ (Face ID на каждую подпись). Проверяет исполнитель — keyguard.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnknownDevice = errors.New("устройство не зарегистрировано")
	ErrRevoked       = errors.New("устройство отозвано")
	ErrPending       = errors.New("устройство не подтверждено")
	ErrBadSignature  = errors.New("подпись неверна")
	ErrStale         = errors.New("действие устарело или из будущего")
	ErrReplay        = errors.New("nonce уже использован")
	ErrWrongOwner    = errors.New("действие относится к другому пользователю")
	ErrBadAction     = errors.New("неверное действие")
)

const (
	MaxAge    = 5 * time.Minute
	MaxFuture = 30 * time.Second
)

type Device struct {
	ID         string
	User       string
	SessionPub *ecdsa.PublicKey // для DPoP/mTLS — НЕ годится для подтверждений
	ConfirmPub *ecdsa.PublicKey // только им подписываются действия
	Revoked    bool
	Pending    bool // зарегистрировано, но не подтверждено: подписывать действия не может
	Name       string
	KeyStorage string // secure_enclave | strongbox | tee | software — сообщает приложение (у Android с аттестацией — из неё)
	Attested   string // что подтверждено аттестацией: "android-key/strongbox", "android-key/tee", "apple-app-attest/app-attest"; "" — ничего
	CSR        string // PKCS#10, подписан ключом сессии (проверено при регистрации)
	CertPEM    string // сертификат устройства для mTLS (после подтверждения)
}

type Devices struct {
	mu sync.RWMutex
	m  map[string]*Device
	p  Persister // nil — только память (тесты); задаёт Server.Restore
}

func NewDevices() *Devices { return &Devices{m: map[string]*Device{}} }

// save — сначала в хранилище, потом в память (persist.go). Вызывается под d.mu.
func (d *Devices) save(x *Device) error {
	if d.p != nil {
		if err := d.p.SaveDevice(x); err != nil {
			return fmt.Errorf("%w: %v", ErrState, err)
		}
	}
	d.m[x.ID] = x
	return nil
}

func (d *Devices) Add(dev *Device) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.save(dev)
}

// change применяет f к копии устройства и сохраняет её; неизвестный id — не ошибка (как раньше).
func (d *Devices) change(id string, f func(*Device)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	x := d.m[id]
	if x == nil {
		return nil
	}
	c := *x
	f(&c)
	return d.save(&c)
}

// Revoke: отзыв действует в памяти, даже если запись в хранилище не удалась (ошибка возвращается вызывающему) —
// отозванное устройство не должно продолжать работать из-за сбоя базы.
func (d *Devices) Revoke(id string) error {
	err := d.change(id, func(x *Device) { x.Revoked = true })
	if err != nil {
		d.mu.Lock()
		if x := d.m[id]; x != nil {
			c := *x
			c.Revoked = true
			d.m[id] = &c
		}
		d.mu.Unlock()
	}
	return err
}
func (d *Devices) Activate(id string) error {
	return d.change(id, func(x *Device) { x.Pending = false })
}

func (d *Devices) SetCert(id, cert string) error {
	return d.change(id, func(x *Device) { x.CertPEM = cert })
}

// RevokeListed — аварийный отзыв по списку из конфигурации (DECK_REVOKE_DEVICES). Нужен, когда отозвать подписью
// некому: единственный администратор потерял единственное устройство, и новое без подтверждения не активируется.
// Список приходит из git через Argo CD — тем же путём, что и любое изменение чувствительных сервисов. Отзыв
// необратим и повторно не выполняется; неизвестные идентификаторы возвращаются отдельно.
func (d *Devices) RevokeListed(ids []string) (revoked, unknown []string, err error) {
	for _, id := range ids {
		if id = strings.TrimSpace(id); id == "" {
			continue
		}
		dev, ok := d.Get(id)
		switch {
		case !ok:
			unknown = append(unknown, id)
		case !dev.Revoked:
			if e := d.Revoke(id); e != nil {
				err = e
			}
			revoked = append(revoked, id)
		}
	}
	return revoked, unknown, err
}

// AnyActive — есть ли хоть одно подтверждённое неотозванное устройство (для bootstrap-администратора).
func (d *Devices) AnyActive() bool { return d.anyActiveOf("") }

// AnyActiveOf — есть ли у пользователя действующее устройство.
func (d *Devices) AnyActiveOf(user string) bool { return user != "" && d.anyActiveOf(user) }

func (d *Devices) anyActiveOf(user string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, x := range d.m {
		if !x.Pending && !x.Revoked && (user == "" || x.User == user) {
			return true
		}
	}
	return false
}

// List — копии устройств пользователя (user == "" — всех), по ID: порядок не должен зависеть от обхода карты.
func (d *Devices) List(user string) []Device {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := []Device{}
	for _, x := range d.m {
		if user == "" || x.User == user {
			out = append(out, *x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (d *Devices) Get(id string) (*Device, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	x, ok := d.m[id]
	if !ok {
		return nil, false
	}
	c := *x
	return &c, true
}

// Nonces — одноразовые номера; хранятся дольше окна времени, поэтому повтор внутри окна невозможен.
type Nonces struct {
	mu     sync.Mutex
	m      map[string]time.Time
	p      Persister // nil — только память; с хранилищем повтор невозможен и после перезапуска
	onErr  func(op string, err error)
	pruned time.Time
}

func NewNonces() *Nonces { return &Nonces{m: map[string]time.Time{}} }

const nonceKeep = MaxAge + MaxFuture + time.Minute

// Use — false, если номер уже использован ИЛИ его не удалось записать в хранилище (тогда запрос отклоняется:
// принять действие, не запомнив его номер, значило бы разрешить повтор после перезапуска).
func (n *Nonces) Use(device, nonce string, now time.Time) bool { return n.use(device, nonce, now, now) }

// UseUntil — как Use, но номер помнится до keepUntil (вызов аттестации живёт дольше окна подписи действий).
func (n *Nonces) UseUntil(device, nonce string, now, keepUntil time.Time) bool {
	return n.use(device, nonce, now, keepUntil)
}

// use: stamp — время, от которого отсчитывается срок хранения записи (обычно now).
func (n *Nonces) use(device, nonce string, now, stamp time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, t := range n.m {
		if now.Sub(t) > nonceKeep {
			delete(n.m, k)
		}
	}
	k := device + "|" + nonce
	if _, seen := n.m[k]; seen {
		return false
	}
	if n.p != nil {
		fresh, err := n.p.UseNonce(device, nonce, stamp)
		if err != nil {
			n.onErr("nonce", err)
			return false
		}
		if !fresh {
			return false
		}
		if now.Sub(n.pruned) > time.Minute || now.Before(n.pruned) {
			n.pruned = now
			if err := n.p.PruneNonces(now.Add(-nonceKeep)); err != nil {
				n.onErr("nonce.prune", err)
			}
		}
	}
	n.m[k] = stamp
	return true
}

type Verifier struct {
	Devices *Devices
	Nonces  *Nonces
	Now     func() time.Time
	// OnUser — подпись пользователя проверена (он активен): для удаления аккаунтов по неактивности.
	OnUser func(user string)
}

// SignedAction — то, что приходит от приложения (через control-plane, который ничего не может изменить):
// компактный JWS, как его делает модуль deck-security (src/deck.ts, signAction):
//
//	заголовок  {"alg":"ES256","typ":"deck-action+jws","kid":"<device_id>"}
//	payload    каноничный JSON действия: поля типа + space, device_id, nonce, ts
//	подпись    ECDSA P-256 над "b64url(заголовок).b64url(payload)", r||s (64 байта), ключ ПОДТВЕРЖДЕНИЯ
type SignedAction struct {
	JWS string `json:"jws"`
}

const ActionTyp = "deck-action+jws"

var b64u = base64.RawURLEncoding

// actionJWS — разобранный, но ещё НЕ проверенный JWS действия.
type actionJWS struct {
	kid    string
	action map[string]any // каноничный JSON payload
	input  string         // "b64url(заголовок).b64url(payload)" — то, что подписано
	sig    []byte
}

// openJWS разбирает компактный JWS действия: строгий заголовок и каноничный payload. Подпись не проверяет.
func openJWS(sa SignedAction) (*actionJWS, error) {
	parts := strings.Split(sa.JWS, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: JWS из трёх частей", ErrBadAction)
	}
	hdrB, e1 := b64u.DecodeString(parts[0])
	payload, e2 := b64u.DecodeString(parts[1])
	sig, e3 := b64u.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, fmt.Errorf("%w: base64url", ErrBadAction)
	}
	hdr, err := ParseStrict(hdrB, false)
	if err != nil || len(hdr) != 3 || s(hdr, "alg") != "ES256" || s(hdr, "typ") != ActionTyp || s(hdr, "kid") == "" {
		return nil, fmt.Errorf("%w: заголовок JWS (нужны alg=ES256, typ=%s, kid)", ErrBadAction, ActionTyp)
	}
	a, err := ParseCanonical(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadAction, err)
	}
	return &actionJWS{kid: s(hdr, "kid"), action: a, input: parts[0] + "." + parts[1], sig: sig}, nil
}

// signedBy — подпись ES256 в форме r||s (64 байта), как её отдаёт чип телефона.
func (j *actionJWS) signedBy(pub *ecdsa.PublicKey) bool {
	if len(j.sig) != 64 {
		return false
	}
	h := sha256.Sum256([]byte(j.input))
	return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(j.sig[:32]), new(big.Int).SetBytes(j.sig[32:]))
}

// Verify возвращает разобранное действие и устройство. Тип действия обязан быть одним из wantTypes.
// Кто подписал — определяется устройством (dev.User), а не полем в действии: приложение его и не шлёт.
func (v *Verifier) Verify(sa SignedAction, wantTypes ...string) (map[string]any, *Device, error) {
	j, err := openJWS(sa)
	if err != nil {
		return nil, nil, err
	}
	a := j.action
	okType := false
	for _, t := range wantTypes {
		okType = okType || s(a, "type") == t
	}
	if !okType {
		return nil, nil, fmt.Errorf("%w: тип %q, ожидали %v", ErrBadAction, s(a, "type"), wantTypes)
	}
	// Точный набор полей типа и конверта (schema.go): подписано может быть только то, что приложение показало.
	if err := ValidateAction(a); err != nil {
		return nil, nil, err
	}
	devID, nonce := s(a, "device_id"), s(a, "nonce")
	if j.kid != devID {
		return nil, nil, fmt.Errorf("%w: kid заголовка не равен device_id действия", ErrBadAction)
	}
	dev, ok := v.Devices.Get(devID)
	if !ok {
		return nil, nil, ErrUnknownDevice
	}
	if dev.Revoked {
		return nil, nil, ErrRevoked
	}
	if dev.Pending {
		return nil, nil, ErrPending
	}
	if !j.signedBy(dev.ConfirmPub) {
		return nil, nil, ErrBadSignature
	}
	ts, err := strconv.ParseInt(num(a, "ts"), 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: ts", ErrBadAction)
	}
	now := v.Now()
	at := time.Unix(ts, 0)
	if now.Sub(at) > MaxAge || at.Sub(now) > MaxFuture {
		return nil, nil, ErrStale
	}
	// nonce расходуется ПОСЛЕДНИМ: невалидный запрос не должен «сжигать» чужой nonce
	if !v.Nonces.Use(devID, nonce, now) {
		return nil, nil, ErrReplay
	}
	if v.OnUser != nil {
		v.OnUser(dev.User)
	}
	return a, dev, nil
}

func s(m map[string]any, k string) string {
	if x, ok := m[k].(string); ok {
		return x
	}
	return ""
}

func num(m map[string]any, k string) string {
	if x, ok := m[k].(json.Number); ok {
		return string(x)
	}
	return ""
}

func strs(m map[string]any, k string) []string {
	a, _ := m[k].([]any)
	var out []string
	for _, e := range a {
		if x, ok := e.(string); ok {
			out = append(out, x)
		}
	}
	return out
}

// usd — сумма из действия (целая или с копейками) → доллары.
func usd(m map[string]any, k string) (float64, bool) {
	x, ok := m[k].(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(x), 64)
	return f, err == nil
}

// dayEnd — дата "2026-10-04" из действия → конец этих суток по UTC (срок «до 4 октября» включает 4-е).
func dayEnd(m map[string]any, k string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", s(m, k))
	return t.Add(24 * time.Hour), err == nil
}
