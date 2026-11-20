// Package controlplane — control-plane Fugu Deck: вход в кластер по приглашению и API приложения.
//
// Сервис доступен из интернета, поэтому ему не доверяют (docs/ARCHITECTURE-v2.md, раздел 2): ключей API он не
// видит, подписи действий не проверяет и не может подменить — регистрацию и подтверждение устройств он передаёт
// в keyguard как есть. Его собственная зона — приглашения: кто, кого и до какого времени позвал.
package controlplane

import (
	"crypto/rand"
	"errors"
	"sort"
	"sync"
	"time"
)

// Invite — приглашение: одноразовый токен, привязанный к нику. В хранилище лежит только хеш токена.
type Invite struct {
	Nick    string
	Inviter string // кто выпустил: ник пользователя или "admin" для приглашения с админского входа
	Expires time.Time
	Used    bool // по приглашению уже зарегистрировано устройство
}

// Pairing — вход ПК по коду с подтверждением на уже подключённом телефоне.
type Pairing struct {
	ID, Code, Nick, Name   string
	SessionJKT, ConfirmJKT string
	SecretHash             string
	Expires                time.Time
	ApprovedBy             string
	Approved               bool
}

// DriveState — OAuth в браузере: state одноразовый, PKCE verifier известен только серверу, срок короткий.
type DriveState struct {
	Nick     string
	Verifier string
	Expires  time.Time
	Used     bool
	Done     bool
}

var ErrNotFound = errors.New("не найдено")

// Store — состояние control-plane. Реализации: MemStore (тесты и стенды) и PGStore (кластер).
type Store interface {
	// CookieKey — ключ подписи cookie приглашения; создаётся при первом обращении и переживает перезапуск.
	CookieKey() ([]byte, error)
	// SpaceKey — закрытый ключ ES256 (PKCS#8) для токенов входа в пространства; создаётся один раз.
	SpaceKey() ([]byte, error)
	PutInvite(hash string, inv Invite) error
	Invite(hash string) (Invite, error)
	// UseInvite помечает приглашение использованным; повторный вызов — ошибка (одноразовость при гонке).
	UseInvite(hash string) error
	PutDriveState(state string, value DriveState) error
	DriveState(state string) (DriveState, error)
	UseDriveState(state string, now time.Time) (DriveState, error)
	FinishDriveState(state string) error
	PutPairing(value Pairing) error
	Pairing(id string) (Pairing, error)
	PairingByCode(code string) (Pairing, error)
	ApprovePairing(id, by string, now time.Time) (Pairing, error)
	// Общие пространства: кто владелец и кто участник — зона control-plane (teams.go).
	CreateTeam(t Team) error
	Team(id string) (Team, error)
	// TeamsOf — общие пространства, где ник участник (владелец — тоже участник с ролью owner).
	TeamsOf(nick string) ([]Team, error)
	Members(team string) ([]Member, error)
	// SetMember добавляет участника или меняет его роль; role == "" — исключить. Владельца менять нельзя.
	SetMember(team, nick, role, by string) error
	DeleteTeam(id string) error
	// TransferTeam — передача владения: newOwner становится владельцем, прежний — редактором.
	TransferTeam(team, newOwner string) error
	// Последний вход пользователя (приложение обращалось к api) и до какого напоминания о неактивности дошли.
	Seen(nick string, at time.Time) error
	SeenUsers() ([]SeenUser, error)
	SetReminded(nick string, level int) error
	// Токены push-уведомлений (FCM) устройств: один на устройство; устройство сменило токен — запись заменяется.
	PutPushToken(nick, device, token string) error
	PushTokens(nick string) ([]PushToken, error)
	DeletePushToken(device string) error
	Ping() error
	// Общее для реплик control-plane (D73). UseNonce — одноразовый ключ (DPoP jti) до until: false — уже был.
	UseNonce(key string, now, until time.Time) (bool, error)
	// TouchSpace и SpaceActivity — последнее обращение к пространству через любую реплику (для сна).
	TouchSpace(name string, at time.Time) error
	SpaceActivity(name string) (time.Time, error)
	// Leader — эта реплика ведёт фоновый цикл name (сон, push): ровно одна из нескольких.
	Leader(name string) bool
}

// SeenUser — когда пользователь последний раз входил; Reminded — за сколько дней до удаления уже напомнили (0 — нет).
type SeenUser struct {
	Nick     string
	Last     time.Time
	Reminded int
}

// PushToken — куда слать уведомления устройству.
type PushToken struct{ Nick, Device, Token string }

type MemStore struct {
	mu       sync.Mutex
	key      []byte
	spaceKey []byte
	invites  map[string]Invite
	teams    map[string]Team
	members  map[string]map[string]Member
	push     map[string]PushToken // устройство → токен
	seen     map[string]SeenUser
	nonces   map[string]time.Time
	activity map[string]time.Time
	drive    map[string]DriveState
	pairings map[string]Pairing
}

// MemStore — одна реплика: всё в памяти, она всегда ведущая.
func (m *MemStore) UseNonce(key string, now, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nonces == nil {
		m.nonces = map[string]time.Time{}
	}
	if len(m.nonces) > 4096 {
		for k, t := range m.nonces {
			if now.After(t) {
				delete(m.nonces, k)
			}
		}
	}
	if t, ok := m.nonces[key]; ok && now.Before(t) {
		return false, nil
	}
	m.nonces[key] = until
	return true, nil
}

func (m *MemStore) TouchSpace(name string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activity == nil {
		m.activity = map[string]time.Time{}
	}
	if at.After(m.activity[name]) {
		m.activity[name] = at
	}
	return nil
}

func (m *MemStore) SpaceActivity(name string) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activity[name], nil
}

func (m *MemStore) Leader(string) bool { return true }

func NewMemStore() *MemStore {
	return &MemStore{invites: map[string]Invite{}, teams: map[string]Team{}, members: map[string]map[string]Member{}}
}

func (m *MemStore) CookieKey() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key == nil {
		m.key = make([]byte, 32)
		if _, err := rand.Read(m.key); err != nil {
			return nil, err
		}
	}
	return m.key, nil
}

func (m *MemStore) SpaceKey() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.spaceKey == nil {
		k, err := newSpaceKey()
		if err != nil {
			return nil, err
		}
		m.spaceKey = k
	}
	return m.spaceKey, nil
}

func (m *MemStore) PutInvite(hash string, inv Invite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites[hash] = inv
	return nil
}

func (m *MemStore) Invite(hash string) (Invite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[hash]
	if !ok {
		return Invite{}, ErrNotFound
	}
	return inv, nil
}

func (m *MemStore) UseInvite(hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[hash]
	if !ok {
		return ErrNotFound
	}
	if inv.Used {
		return errors.New("приглашение уже использовано")
	}
	inv.Used = true
	m.invites[hash] = inv
	return nil
}

func (m *MemStore) PutDriveState(state string, value DriveState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.drive == nil {
		m.drive = map[string]DriveState{}
	}
	m.drive[state] = value
	return nil
}

func (m *MemStore) DriveState(state string) (DriveState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.drive[state]
	if !ok {
		return DriveState{}, ErrNotFound
	}
	return value, nil
}

func (m *MemStore) UseDriveState(state string, now time.Time) (DriveState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.drive[state]
	if !ok || value.Used || !now.Before(value.Expires) {
		return DriveState{}, ErrNotFound
	}
	value.Used = true
	m.drive[state] = value
	return value, nil
}

func (m *MemStore) FinishDriveState(state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.drive[state]
	if !ok {
		return ErrNotFound
	}
	value.Done = true
	m.drive[state] = value
	return nil
}

func (m *MemStore) Ping() error { return nil }

func (m *MemStore) CreateTeam(t Team) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.teams[t.ID]; ok {
		return errors.New("такое пространство уже есть")
	}
	m.teams[t.ID] = t
	m.members[t.ID] = map[string]Member{t.Owner: {Nick: t.Owner, Role: "owner"}}
	return nil
}

func (m *MemStore) Team(id string) (Team, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.teams[id]
	if !ok {
		return Team{}, ErrNotFound
	}
	return t, nil
}

func (m *MemStore) TeamsOf(nick string) ([]Team, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Team{}
	for id, t := range m.teams {
		if _, ok := m.members[id][nick]; ok {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemStore) Members(team string) ([]Member, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Member{}
	for _, mb := range m.members[team] {
		out = append(out, mb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nick < out[j].Nick })
	return out, nil
}

func (m *MemStore) SetMember(team, nick, role, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.teams[team]
	if !ok {
		return ErrNotFound
	}
	if nick == t.Owner {
		return ErrOwnerRole
	}
	if role == "" {
		delete(m.members[team], nick)
		return nil
	}
	m.members[team][nick] = Member{Nick: nick, Role: role}
	return nil
}

func (m *MemStore) DeleteTeam(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.teams, id)
	delete(m.members, id)
	return nil
}

func (m *MemStore) PutPushToken(nick, device, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.push == nil {
		m.push = map[string]PushToken{}
	}
	m.push[device] = PushToken{Nick: nick, Device: device, Token: token}
	return nil
}

func (m *MemStore) PushTokens(nick string) ([]PushToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PushToken
	for _, t := range m.push {
		if t.Nick == nick {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Device < out[j].Device })
	return out, nil
}

func (m *MemStore) DeletePushToken(device string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.push, device)
	return nil
}

func (m *MemStore) TransferTeam(team, newOwner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.teams[team]
	if !ok {
		return ErrNotFound
	}
	if _, member := m.members[team][newOwner]; !member {
		return ErrNotFound
	}
	m.members[team][t.Owner] = Member{Nick: t.Owner, Role: "editor"}
	m.members[team][newOwner] = Member{Nick: newOwner, Role: "owner"}
	t.Owner = newOwner
	m.teams[team] = t
	return nil
}

func (m *MemStore) Seen(nick string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[string]SeenUser{}
	}
	m.seen[nick] = SeenUser{Nick: nick, Last: at}
	return nil
}

func (m *MemStore) SeenUsers() ([]SeenUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []SeenUser{}
	for _, u := range m.seen {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nick < out[j].Nick })
	return out, nil
}

func (m *MemStore) SetReminded(nick string, level int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.seen[nick]
	u.Reminded = level
	m.seen[nick] = u
	return nil
}
