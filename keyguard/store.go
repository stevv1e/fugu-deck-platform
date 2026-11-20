package keyguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ---------------- ключи ----------------

var ErrNoKey = errors.New("ключ не найден")

type KeyStore interface {
	Put(ctx context.Context, user, provider, key string) error
	Get(ctx context.Context, user, provider string) (string, error)
	// Delete удаляет ключ со всеми версиями; ключа нет — не ошибка.
	Delete(ctx context.Context, user, provider string) error
}

type MemStore struct {
	mu sync.RWMutex
	m  map[string]string
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]string{}} }
func (m *MemStore) Put(_ context.Context, u, p, k string) error {
	m.mu.Lock()
	m.m[u+"/"+p] = k
	m.mu.Unlock()
	return nil
}
func (m *MemStore) Get(_ context.Context, u, p string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.m[u+"/"+p]
	if !ok {
		return "", ErrNoKey
	}
	return k, nil
}
func (m *MemStore) Delete(_ context.Context, u, p string) error {
	m.mu.Lock()
	delete(m.m, u+"/"+p)
	m.mu.Unlock()
	return nil
}

// BaoStore — OpenBao KV v2, путь deck/data/keys/<user>/<provider>; запись с cas (политика keyguard.hcl, cas_required).
type BaoStore struct {
	Addr, Mount string
	Token       func(ctx context.Context) (string, error) // в бою — вход по проецируемому токену (k8s auth)
	HTTP        *http.Client
}

var safeSeg = func(x string) bool {
	if x == "" || len(x) > 64 {
		return false
	}
	for _, c := range x {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (b *BaoStore) path(kind, u, p string) (string, error) {
	if !safeSeg(u) || !safeSeg(p) { // никаких "../", "%2f" и т.п. в пути OpenBao
		return "", fmt.Errorf("недопустимое имя: %q/%q", u, p)
	}
	return fmt.Sprintf("%s/v1/%s/%s/keys/%s/%s", b.Addr, b.Mount, kind, url.PathEscape(u), url.PathEscape(p)), nil
}

func (b *BaoStore) do(ctx context.Context, method, u string, body any) (int, map[string]any, error) {
	tok, err := b.Token(ctx)
	if err != nil {
		return 0, nil, err
	}
	var rd *bytes.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequestWithContext(ctx, method, u, rd)
	req.Header.Set("X-Vault-Token", tok)
	req.Header.Set("Content-Type", "application/json")
	r, err := b.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer r.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out, nil
}

func (b *BaoStore) Put(ctx context.Context, u, p, key string) error {
	mu, err := b.path("metadata", u, p)
	if err != nil {
		return err
	}
	cas := 0
	if st, md, _ := b.do(ctx, "GET", mu, nil); st == 200 {
		if d, ok := md["data"].(map[string]any); ok {
			if v, ok := d["current_version"].(float64); ok {
				cas = int(v)
			}
		}
	}
	du, _ := b.path("data", u, p)
	st, _, err := b.do(ctx, "POST", du, map[string]any{"options": map[string]any{"cas": cas}, "data": map[string]any{"key": key}})
	if err != nil {
		return err
	}
	if st != 200 && st != 204 {
		return fmt.Errorf("openbao put: %d", st)
	}
	return nil
}

func (b *BaoStore) Get(ctx context.Context, u, p string) (string, error) {
	du, err := b.path("data", u, p)
	if err != nil {
		return "", err
	}
	st, j, err := b.do(ctx, "GET", du, nil)
	if err != nil {
		return "", err
	}
	if st == 404 {
		return "", ErrNoKey
	}
	if st != 200 {
		return "", fmt.Errorf("openbao get: %d", st)
	}
	d, _ := j["data"].(map[string]any)
	dd, _ := d["data"].(map[string]any)
	k, _ := dd["key"].(string)
	if k == "" {
		return "", ErrNoKey
	}
	return k, nil
}

// Delete — DELETE metadata: все версии ключа удаляются безвозвратно (политика keyguard.hcl, keys/+/+).
func (b *BaoStore) Delete(ctx context.Context, u, p string) error {
	mu, err := b.path("metadata", u, p)
	if err != nil {
		return err
	}
	st, _, err := b.do(ctx, "DELETE", mu, nil)
	if err != nil {
		return err
	}
	if st != 200 && st != 204 && st != 404 {
		return fmt.Errorf("openbao delete: %d", st)
	}
	return nil
}

// ---------------- учёт расходов ----------------
// Резерв до запроса (максимально возможная стоимость), пересчёт по факту после. Под одной блокировкой проверяются
// ВСЕ бюджеты запроса сразу — параллельные запросы не могут вместе превысить лимит.

var ErrLimit = errors.New("лимит расходов исчерпан")

type Ledger struct {
	mu       sync.Mutex
	limit    map[string]float64
	spent    map[string]float64
	reserved map[string]float64
	p        Persister // nil — только память; задаёт Server.Restore
	onErr    func(op string, err error)
}

func NewLedger() *Ledger {
	return &Ledger{limit: map[string]float64{}, spent: map[string]float64{}, reserved: map[string]float64{}}
}

func (l *Ledger) SetLimit(k string, usd float64) error { return l.setLimit(k, usd, false) }

// SetLimitOnce — только если лимита ещё нет.
func (l *Ledger) SetLimitOnce(k string, usd float64) error { return l.setLimit(k, usd, true) }

func (l *Ledger) setLimit(k string, usd float64, once bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.limit[k]; ok && once {
		return nil
	}
	if l.p != nil {
		if err := l.p.SetLimit(k, usd, once); err != nil {
			return fmt.Errorf("%w: %v", ErrState, err)
		}
	}
	l.limit[k] = usd
	return nil
}
func (l *Ledger) Spent(k string) float64 { l.mu.Lock(); defer l.mu.Unlock(); return l.spent[k] }

// Limit — установленный лимит бюджета (ok=false — не задан).
func (l *Ledger) Limit(k string) (float64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.limit[k]
	return v, ok
}

type Reservation struct {
	l    *Ledger
	keys []string
	amt  float64
	once sync.Once
}

func (l *Ledger) Reserve(keys []string, amt float64) (*Reservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		if lim, ok := l.limit[k]; ok && l.spent[k]+l.reserved[k]+amt > lim+1e-9 {
			return nil, fmt.Errorf("%w (%s)", ErrLimit, k)
		}
	}
	// Резерв записывается в хранилище как расход ещё ДО запроса к провайдеру: упадём посреди запроса — в базе
	// останется резерв (учёт завысится, а не обнулится). Settle уточняет его до факта.
	if l.p != nil {
		if err := l.p.AddSpent(keys, amt); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrState, err)
		}
	}
	for _, k := range keys {
		l.reserved[k] += amt
	}
	return &Reservation{l: l, keys: keys, amt: amt}, nil
}

// Settle — фактическая стоимость. Если провайдер не сообщил usage, списывается весь резерв (fail-safe).
// Факт НЕ ограничивается резервом: резерв — оценка (вход ≈ байты тела), а провайдер может насчитать больше
// (скрытые токены оркестрации Sakana Fugu, сжатый текст в PDF, кэш промптов). Ограничение сверху занижало бы
// учёт и тихо пробивало лимит спонсора. Поэтому лимит может быть превышен не более чем одним запросом —
// следующие отклоняются. Вторая линия — лимиты расходов на стороне провайдера (docs/keyguard.md).
func (r *Reservation) Settle(actual float64, known bool) (charged float64) {
	r.once.Do(func() {
		if !known {
			actual = r.amt
		}
		charged = actual
		r.l.mu.Lock()
		// Не записалось уточнение: в памяти — факт, в базе остаётся резерв. Ответ провайдера уже ушёл клиенту,
		// отменять нечего; расхождение попадёт в журнал и исчезнет только с перезапуском (в пользу резерва).
		if r.l.p != nil && actual != r.amt {
			if err := r.l.p.AddSpent(r.keys, actual-r.amt); err != nil {
				r.l.onErr("ledger.settle", err)
			}
		}
		for _, k := range r.keys {
			r.l.reserved[k] -= r.amt
			r.l.spent[k] += actual
		}
		r.l.mu.Unlock()
	})
	return charged
}

// ---------------- разрешения спонсоров ----------------

type Grant struct {
	ID, Space, Chat, Proposal, Provider, Model, Sponsor string
	LimitUSD, PerMemberUSDDay                           float64
	Until, KeyUntil                                     time.Time
	Members                                             []string
	Active, Revoked                                     bool
}

type Grants struct {
	mu sync.Mutex
	m  map[string]*Grant
	p  Persister // nil — только память; задаёт Server.Restore
}

func NewGrants() *Grants { return &Grants{m: map[string]*Grant{}} }

// save — сначала в хранилище, потом в память. Вызывается под g.mu.
func (g *Grants) save(x *Grant) error {
	if g.p != nil {
		if err := g.p.SaveGrant(x); err != nil {
			return fmt.Errorf("%w: %v", ErrState, err)
		}
	}
	g.m[x.ID] = x
	return nil
}

// Put не перезаписывает: существующее разрешение (и его счётчик расходов) нельзя подменить новым с тем же id.
// false без ошибки — такое разрешение уже есть.
func (g *Grants) Put(x *Grant) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, dup := g.m[x.ID]; dup {
		return false, nil
	}
	if err := g.save(x); err != nil {
		return false, err
	}
	return true, nil
}
func (g *Grants) Get(id string) (*Grant, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	x, ok := g.m[id]
	if !ok {
		return nil, false
	}
	c := *x
	return &c, true
}

// Update применяет f к копии разрешения и сохраняет её. false без ошибки — разрешения с таким id нет.
func (g *Grants) Update(id string, f func(*Grant)) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	x, ok := g.m[id]
	if !ok {
		return false, nil
	}
	c := *x
	f(&c)
	return true, g.save(&c)
}

// Revoke — отзыв разрешений спонсора по пространству, чату и предложению; возвращает число отозванных.
// Отзыв действует в памяти, даже если запись в хранилище не удалась (ошибка возвращается вызывающему).
func (g *Grants) Revoke(space, chat, proposal, sponsor string) (n int, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, x := range g.m {
		if x.Space == space && x.Chat == chat && x.Proposal == proposal && x.Sponsor == sponsor && !x.Revoked {
			c := *x
			c.Revoked = true
			if e := g.save(&c); e != nil {
				err = e
				g.m[id] = &c
			}
			n++
		}
	}
	return n, err
}

// RevokeSponsor — все разрешения, которые выдал спонсор (удаление аккаунта); возвращает число отозванных.
func (g *Grants) RevokeSponsor(sponsor string) (n int, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, x := range g.m {
		if x.Sponsor == sponsor && !x.Revoked {
			c := *x
			c.Revoked = true
			if e := g.save(&c); e != nil {
				err = e
				g.m[id] = &c
			}
			n++
		}
	}
	return n, err
}

// MemberLeft — участника исключили из пространства: его разрешения отозваны, из чужих он убран из допущенных.
// Только сужает права. Возвращает (отозвано, сужено).
func (g *Grants) MemberLeft(space, member string) (revoked, trimmed int, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, x := range g.m {
		if x.Space != space || x.Revoked {
			continue
		}
		c := *x
		switch {
		case x.Sponsor == member:
			c.Revoked = true
			revoked++
		case contains(x.Members, member):
			c.Members = nil
			for _, m := range x.Members {
				if m != member {
					c.Members = append(c.Members, m)
				}
			}
			trimmed++
		default:
			continue
		}
		if e := g.save(&c); e != nil {
			err = e
			g.m[id] = &c
		}
	}
	return revoked, trimmed, err
}

// Find — действующее разрешение для чата/провайдера/модели в пространстве.
func (g *Grants) Find(space, chat, provider, model string, now time.Time) (*Grant, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.m {
		if x.Space == space && x.Chat == chat && x.Provider == provider && x.Model == model &&
			x.Active && !x.Revoked && now.Before(x.Until) && now.Before(x.KeyUntil) {
			c := *x
			return &c, true
		}
	}
	return nil, false
}

func contains(a []string, x string) bool {
	for _, e := range a {
		if e == x {
			return true
		}
	}
	return false
}

func lower(x string) string { return strings.ToLower(x) }
