package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// PGStore — состояние в Postgres (база controlplane). Таблицы создаются при старте. Общее для реплик (D73):
// одноразовые ключи DPoP, активность пространств и ведущая реплика фоновых циклов (advisory lock на своём соединении).
type PGStore struct {
	DB *sql.DB

	mu      sync.Mutex
	leaders map[string]*sql.Conn
	nonceN  int
}

const pgSchema = `
CREATE TABLE IF NOT EXISTS cp_settings (name text PRIMARY KEY, value bytea NOT NULL);
CREATE TABLE IF NOT EXISTS cp_invites (
  hash    text PRIMARY KEY,
  nick    text NOT NULL,
  inviter text NOT NULL,
  expires timestamptz NOT NULL,
  used_at timestamptz,
  created timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cp_teams (
  id      text PRIMARY KEY,
  title   text NOT NULL,
  owner   text NOT NULL,
  created timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cp_team_members (
  team     text NOT NULL REFERENCES cp_teams(id) ON DELETE CASCADE,
  nick     text NOT NULL,
  role     text NOT NULL,
  added_by text NOT NULL,
  added    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (team, nick)
);
CREATE INDEX IF NOT EXISTS cp_team_members_nick ON cp_team_members (nick);
CREATE TABLE IF NOT EXISTS cp_push_tokens (
  device  text PRIMARY KEY,
  nick    text NOT NULL,
  token   text NOT NULL,
  updated timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cp_push_tokens_nick ON cp_push_tokens (nick);
CREATE TABLE IF NOT EXISTS cp_users_seen (
  nick     text PRIMARY KEY,
  last     timestamptz NOT NULL,
  reminded integer NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS cp_nonces (key text PRIMARY KEY, until timestamptz NOT NULL);
CREATE INDEX IF NOT EXISTS cp_nonces_until ON cp_nonces (until);
CREATE TABLE IF NOT EXISTS cp_space_activity (space text PRIMARY KEY, last timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS cp_drive_oauth (
  state text PRIMARY KEY,
  nick text NOT NULL,
  verifier text NOT NULL,
  expires timestamptz NOT NULL,
  used_at timestamptz,
  done_at timestamptz
);
CREATE TABLE IF NOT EXISTS cp_pairings (
  id text PRIMARY KEY,
  code text UNIQUE NOT NULL,
  nick text NOT NULL,
  name text NOT NULL,
  session_jkt text NOT NULL,
  confirm_jkt text NOT NULL,
  secret_hash text NOT NULL,
  expires timestamptz NOT NULL,
  approved_by text,
  approved_at timestamptz,
  created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cp_pairings_expires ON cp_pairings (expires);`

func OpenPG(dsn string) (*PGStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetConnMaxLifetime(30 * time.Minute)
	if _, err := db.Exec(pgSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &PGStore{DB: db}, nil
}

func (p *PGStore) CookieKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	// Первый записавший выигрывает; остальные читают его ключ.
	if _, err := p.DB.Exec(`INSERT INTO cp_settings (name, value) VALUES ('cookie_key', $1) ON CONFLICT DO NOTHING`, k); err != nil {
		return nil, err
	}
	err := p.DB.QueryRow(`SELECT value FROM cp_settings WHERE name = 'cookie_key'`).Scan(&k)
	return k, err
}

func (p *PGStore) SpaceKey() ([]byte, error) {
	k, err := newSpaceKey()
	if err != nil {
		return nil, err
	}
	// Первый записавший выигрывает; остальные читают его ключ.
	if _, err := p.DB.Exec(`INSERT INTO cp_settings (name, value) VALUES ('space_key', $1) ON CONFLICT DO NOTHING`, k); err != nil {
		return nil, err
	}
	err = p.DB.QueryRow(`SELECT value FROM cp_settings WHERE name = 'space_key'`).Scan(&k)
	return k, err
}

func (p *PGStore) PutInvite(hash string, inv Invite) error {
	_, err := p.DB.Exec(`INSERT INTO cp_invites (hash, nick, inviter, expires) VALUES ($1, $2, $3, $4)`,
		hash, inv.Nick, inv.Inviter, inv.Expires)
	return err
}

func (p *PGStore) Invite(hash string) (Invite, error) {
	var inv Invite
	var used sql.NullTime
	err := p.DB.QueryRow(`SELECT nick, inviter, expires, used_at FROM cp_invites WHERE hash = $1`, hash).
		Scan(&inv.Nick, &inv.Inviter, &inv.Expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrNotFound
	}
	inv.Used = used.Valid
	return inv, err
}

func (p *PGStore) UseInvite(hash string) error {
	r, err := p.DB.Exec(`UPDATE cp_invites SET used_at = now() WHERE hash = $1 AND used_at IS NULL`, hash)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return errors.New("приглашение уже использовано")
	}
	return nil
}

func (p *PGStore) PutDriveState(state string, value DriveState) error {
	_, err := p.DB.Exec(`INSERT INTO cp_drive_oauth (state, nick, verifier, expires) VALUES ($1,$2,$3,$4)`,
		state, value.Nick, value.Verifier, value.Expires)
	return err
}

func (p *PGStore) DriveState(state string) (DriveState, error) {
	var out DriveState
	var used, done sql.NullTime
	err := p.DB.QueryRow(`SELECT nick, verifier, expires, used_at, done_at FROM cp_drive_oauth WHERE state=$1`, state).
		Scan(&out.Nick, &out.Verifier, &out.Expires, &used, &done)
	if errors.Is(err, sql.ErrNoRows) {
		return DriveState{}, ErrNotFound
	}
	out.Used, out.Done = used.Valid, done.Valid
	return out, err
}

func (p *PGStore) UseDriveState(state string, now time.Time) (DriveState, error) {
	out, err := p.DriveState(state)
	if err != nil || out.Used || !now.Before(out.Expires) {
		return DriveState{}, ErrNotFound
	}
	r, err := p.DB.Exec(`UPDATE cp_drive_oauth SET used_at=now() WHERE state=$1 AND used_at IS NULL`, state)
	if err != nil {
		return DriveState{}, err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return DriveState{}, ErrNotFound
	}
	out.Used = true
	return out, nil
}

func (p *PGStore) FinishDriveState(state string) error {
	_, err := p.DB.Exec(`UPDATE cp_drive_oauth SET done_at=now() WHERE state=$1`, state)
	return err
}

func (p *PGStore) CreateTeam(t Team) error {
	tx, err := p.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO cp_teams (id, title, owner) VALUES ($1, $2, $3)`, t.ID, t.Title, t.Owner); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO cp_team_members (team, nick, role, added_by) VALUES ($1, $2, 'owner', $2)`, t.ID, t.Owner); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *PGStore) Team(id string) (Team, error) {
	t := Team{ID: id}
	err := p.DB.QueryRow(`SELECT title, owner FROM cp_teams WHERE id = $1`, id).Scan(&t.Title, &t.Owner)
	if errors.Is(err, sql.ErrNoRows) {
		return Team{}, ErrNotFound
	}
	return t, err
}

func (p *PGStore) TeamsOf(nick string) ([]Team, error) {
	rows, err := p.DB.Query(`SELECT t.id, t.title, t.owner FROM cp_teams t JOIN cp_team_members m ON m.team = t.id
		WHERE m.nick = $1 ORDER BY t.id`, nick)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Team{}
	for rows.Next() {
		var t Team
		if err := rows.Scan(&t.ID, &t.Title, &t.Owner); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *PGStore) Members(team string) ([]Member, error) {
	rows, err := p.DB.Query(`SELECT nick, role FROM cp_team_members WHERE team = $1 ORDER BY nick`, team)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.Nick, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *PGStore) SetMember(team, nick, role, by string) error {
	t, err := p.Team(team)
	if err != nil {
		return err
	}
	if nick == t.Owner {
		return ErrOwnerRole
	}
	if role == "" {
		_, err = p.DB.Exec(`DELETE FROM cp_team_members WHERE team = $1 AND nick = $2`, team, nick)
		return err
	}
	_, err = p.DB.Exec(`INSERT INTO cp_team_members (team, nick, role, added_by) VALUES ($1, $2, $3, $4)
		ON CONFLICT (team, nick) DO UPDATE SET role = EXCLUDED.role, added_by = EXCLUDED.added_by, added = now()`, team, nick, role, by)
	return err
}

func (p *PGStore) DeleteTeam(id string) error {
	_, err := p.DB.Exec(`DELETE FROM cp_teams WHERE id = $1`, id)
	return err
}

func (p *PGStore) Ping() error { return p.DB.Ping() }

func (p *PGStore) PutPushToken(nick, device, token string) error {
	_, err := p.DB.Exec(`INSERT INTO cp_push_tokens (device, nick, token, updated) VALUES ($1, $2, $3, now())
ON CONFLICT (device) DO UPDATE SET nick = EXCLUDED.nick, token = EXCLUDED.token, updated = now()`, device, nick, token)
	return err
}

func (p *PGStore) PushTokens(nick string) ([]PushToken, error) {
	rows, err := p.DB.Query(`SELECT device, token FROM cp_push_tokens WHERE nick = $1 ORDER BY device`, nick)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushToken
	for rows.Next() {
		t := PushToken{Nick: nick}
		if err := rows.Scan(&t.Device, &t.Token); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *PGStore) DeletePushToken(device string) error {
	_, err := p.DB.Exec(`DELETE FROM cp_push_tokens WHERE device = $1`, device)
	return err
}

func (p *PGStore) TransferTeam(team, newOwner string) error {
	tx, err := p.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old string
	if err := tx.QueryRow(`SELECT owner FROM cp_teams WHERE id = $1 FOR UPDATE`, team).Scan(&old); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	res, err := tx.Exec(`UPDATE cp_team_members SET role = 'owner' WHERE team = $1 AND nick = $2`, team, newOwner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound // передать можно только участнику
	}
	if _, err := tx.Exec(`UPDATE cp_team_members SET role = 'editor' WHERE team = $1 AND nick = $2`, team, old); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE cp_teams SET owner = $2 WHERE id = $1`, team, newOwner); err != nil {
		return err
	}
	return tx.Commit()
}

// Seen — отметка входа; сбрасывает напоминания о неактивности.
func (p *PGStore) Seen(nick string, at time.Time) error {
	_, err := p.DB.Exec(`INSERT INTO cp_users_seen (nick, last, reminded) VALUES ($1, $2, 0)
ON CONFLICT (nick) DO UPDATE SET last = GREATEST(cp_users_seen.last, EXCLUDED.last), reminded = 0`, nick, at)
	return err
}

func (p *PGStore) SeenUsers() ([]SeenUser, error) {
	rows, err := p.DB.Query(`SELECT nick, last, reminded FROM cp_users_seen ORDER BY nick`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SeenUser
	for rows.Next() {
		var u SeenUser
		if err := rows.Scan(&u.Nick, &u.Last, &u.Reminded); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (p *PGStore) SetReminded(nick string, level int) error {
	_, err := p.DB.Exec(`UPDATE cp_users_seen SET reminded = $2 WHERE nick = $1`, nick, level)
	return err
}

func (p *PGStore) UseNonce(key string, now, until time.Time) (bool, error) {
	p.mu.Lock()
	p.nonceN++
	sweep := p.nonceN%500 == 0
	p.mu.Unlock()
	if sweep {
		p.DB.Exec(`DELETE FROM cp_nonces WHERE until < $1`, now)
	}
	r, err := p.DB.Exec(`INSERT INTO cp_nonces (key, until) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET until = EXCLUDED.until WHERE cp_nonces.until < $3`, key, until, now)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (p *PGStore) TouchSpace(name string, at time.Time) error {
	_, err := p.DB.Exec(`INSERT INTO cp_space_activity (space, last) VALUES ($1, $2)
		ON CONFLICT (space) DO UPDATE SET last = GREATEST(cp_space_activity.last, EXCLUDED.last)`, name, at)
	return err
}

func (p *PGStore) SpaceActivity(name string) (time.Time, error) {
	var t time.Time
	err := p.DB.QueryRow(`SELECT last FROM cp_space_activity WHERE space = $1`, name).Scan(&t)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return t, err
}

// Leader — держит pg_try_advisory_lock на отдельном соединении: соединение оборвалось (реплика упала или сеть) —
// блокировку снимает сам Postgres, и цикл подхватывает другая реплика.
func (p *PGStore) Leader(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c := p.leaders[name]; c != nil {
		if c.PingContext(ctx) == nil {
			return true
		}
		// соединение с блокировкой сломано: выбросить, а не вернуть в пул (Close вернул бы его туда)
		c.Raw(func(any) error { return driver.ErrBadConn })
		c.Close()
		delete(p.leaders, name)
	}
	c, err := p.DB.Conn(ctx)
	if err != nil {
		return false
	}
	var ok bool
	if err := c.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, "deck-cp:"+name).Scan(&ok); err != nil || !ok {
		c.Close()
		return false
	}
	if p.leaders == nil {
		p.leaders = map[string]*sql.Conn{}
	}
	p.leaders[name] = c
	return true
}
