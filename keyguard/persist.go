package keyguard

// Долговременное состояние keyguard: устройства, одноразовые номера, разрешения спонсоров, лимиты и расходы.
//
// Память остаётся рабочей копией (чтения не ходят в базу), но КАЖДОЕ изменение сначала записывается в хранилище и
// только потом применяется. Не записалось — изменение не происходит, запрос получает отказ (fail closed).
// После перезапуска состояние восстанавливается из хранилища, поэтому:
//   - подписанное действие нельзя повторить: nonce уже лежит в базе;
//   - лимиты спонсоров не начинаются заново: расходы лежат в базе;
//   - отозванное устройство остаётся отозванным, неподтверждённое — неподтверждённым.
//
// Расход записывается ДО запроса к провайдеру (весь резерв) и уточняется после ответа: если keyguard упадёт посреди
// запроса, в базе останется резерв — учёт завысится, но не занизится.
//
// Экземпляр должен быть один: рабочая копия в памяти у двух процессов разошлась бы. Это обеспечивает хранилище
// (PGState держит блокировку в базе), а не число реплик в манифесте.

import (
	"context"
	"errors"
	"time"
)

// ErrState — хранилище состояния недоступно: изменение не записано и не применено.
var ErrState = errors.New("хранилище состояния недоступно")

type Snapshot struct {
	Devices []*Device
	Grants  []*Grant
	Limits  map[string]float64
	Spent   map[string]float64
}

type Persister interface {
	Load(ctx context.Context) (*Snapshot, error)
	SaveDevice(d *Device) error
	// UseNonce записывает номер; fresh=false — он уже был (повтор). Проверка и запись — одно атомарное действие.
	UseNonce(scope, nonce string, at time.Time) (fresh bool, err error)
	PruneNonces(before time.Time) error
	SaveGrant(g *Grant) error
	// SetLimit: once=true — только если лимита ещё нет (дневной лимит участника не сбрасывается повторной установкой).
	SetLimit(key string, usd float64, once bool) error
	// AddSpent прибавляет usd (может быть отрицательным — уточнение резерва) ко всем бюджетам разом.
	AddSpent(keys []string, usd float64) error
}

// Restore загружает состояние из хранилища и включает запись изменений. Вызывается один раз до приёма запросов.
func (s *Server) Restore(ctx context.Context, p Persister) error {
	snap, err := p.Load(ctx)
	if err != nil {
		return err
	}
	onErr := func(op string, err error) {
		s.Log.Printf("event=state.error op=%s err=%q", op, err.Error())
	}
	d := s.Verifier.Devices
	d.mu.Lock()
	for _, x := range snap.Devices {
		d.m[x.ID] = x
	}
	d.p = p
	d.mu.Unlock()

	n := s.Verifier.Nonces
	n.mu.Lock()
	n.p, n.onErr = p, onErr
	n.mu.Unlock()

	g := s.Grants
	g.mu.Lock()
	for _, x := range snap.Grants {
		g.m[x.ID] = x
	}
	g.p = p
	g.mu.Unlock()

	l := s.Ledger
	l.mu.Lock()
	for k, v := range snap.Limits {
		l.limit[k] = v
	}
	for k, v := range snap.Spent {
		l.spent[k] = v
	}
	l.p, l.onErr = p, onErr
	l.mu.Unlock()
	s.Log.Printf("event=state.restored devices=%d grants=%d budgets=%d", len(snap.Devices), len(snap.Grants), len(snap.Spent))
	return nil
}

// ---------------- хранилище в памяти (тесты перезапуска без базы) ----------------

// MemState хранит то же, что PGState, и переживает «перезапуск» — создание нового Server поверх того же MemState.
type MemState struct {
	Fail    error // если задано — все операции возвращают эту ошибку (проверка отказа хранилища)
	devices map[string]Device
	grants  map[string]Grant
	nonces  map[string]time.Time
	limits  map[string]float64
	spent   map[string]float64
}

func NewMemState() *MemState {
	return &MemState{devices: map[string]Device{}, grants: map[string]Grant{}, nonces: map[string]time.Time{},
		limits: map[string]float64{}, spent: map[string]float64{}}
}

// MemState вызывается только под блокировками хранилищ памяти и из одного теста — своя блокировка ему не нужна,
// но устройства, nonce, разрешения и учёт блокируются РАЗНЫМИ мьютексами, поэтому карты у каждого свои.

func (m *MemState) Load(context.Context) (*Snapshot, error) {
	if m.Fail != nil {
		return nil, m.Fail
	}
	s := &Snapshot{Limits: map[string]float64{}, Spent: map[string]float64{}}
	for _, d := range m.devices {
		c := d
		s.Devices = append(s.Devices, &c)
	}
	for _, g := range m.grants {
		c := g
		c.Members = append([]string(nil), g.Members...)
		s.Grants = append(s.Grants, &c)
	}
	for k, v := range m.limits {
		s.Limits[k] = v
	}
	for k, v := range m.spent {
		s.Spent[k] = v
	}
	return s, nil
}

func (m *MemState) SaveDevice(d *Device) error {
	if m.Fail == nil {
		m.devices[d.ID] = *d
	}
	return m.Fail
}

func (m *MemState) UseNonce(scope, nonce string, at time.Time) (bool, error) {
	if m.Fail != nil {
		return false, m.Fail
	}
	k := scope + "|" + nonce
	if _, seen := m.nonces[k]; seen {
		return false, nil
	}
	m.nonces[k] = at
	return true, nil
}

func (m *MemState) PruneNonces(before time.Time) error {
	if m.Fail != nil {
		return m.Fail
	}
	for k, t := range m.nonces {
		if t.Before(before) {
			delete(m.nonces, k)
		}
	}
	return nil
}

func (m *MemState) SaveGrant(g *Grant) error {
	if m.Fail == nil {
		c := *g
		c.Members = append([]string(nil), g.Members...)
		m.grants[g.ID] = c
	}
	return m.Fail
}

func (m *MemState) SetLimit(key string, usd float64, once bool) error {
	if m.Fail != nil {
		return m.Fail
	}
	if _, ok := m.limits[key]; !ok || !once {
		m.limits[key] = usd
	}
	return nil
}

func (m *MemState) AddSpent(keys []string, usd float64) error {
	if m.Fail != nil {
		return m.Fail
	}
	for _, k := range keys {
		m.spent[k] += usd
	}
	return nil
}
