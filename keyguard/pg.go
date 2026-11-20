package keyguard

// PGState — состояние keyguard в Postgres (база keyguard кластера CNPG, своя роль, только TLS — pg_hba в
// fugu-deck-infra/kubernetes/platform/cnpg/cluster.yaml). Единственная внешняя зависимость keyguard — драйвер
// github.com/lib/pq (у него самого зависимостей нет).
//
// Единственность экземпляра: при открытии берётся сессионная блокировка pg_advisory_lock на отдельном соединении и
// держится всё время работы. Второй keyguard ждёт её и запросов не принимает; если соединение с блокировкой
// оборвалось, вызывается onLost — процесс обязан завершиться (его рабочая копия в памяти больше не единственная).

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/lib/pq"
)

const pgLockKey = 0x6b657967756172 // "keyguar" — ключ блокировки единственного экземпляра

var lockCheckEvery = 5 * time.Second

const pgSchema = `
CREATE TABLE IF NOT EXISTS kg_devices (
  id text PRIMARY KEY, usr text NOT NULL, session_pub bytea NOT NULL, confirm_pub bytea NOT NULL,
  revoked boolean NOT NULL, pending boolean NOT NULL, name text NOT NULL, key_storage text NOT NULL,
  csr text NOT NULL, cert_pem text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE kg_devices ADD COLUMN IF NOT EXISTS attested text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS kg_nonces (
  scope text NOT NULL, nonce text NOT NULL, used_at timestamptz NOT NULL, PRIMARY KEY (scope, nonce));
CREATE INDEX IF NOT EXISTS kg_nonces_used_at ON kg_nonces (used_at);
CREATE TABLE IF NOT EXISTS kg_grants (
  id text PRIMARY KEY, space text NOT NULL, chat text NOT NULL, proposal text NOT NULL, provider text NOT NULL,
  model text NOT NULL, sponsor text NOT NULL, limit_usd double precision NOT NULL,
  per_member_usd_day double precision NOT NULL, until_at timestamptz NOT NULL, key_until_at timestamptz NOT NULL,
  members jsonb NOT NULL, active boolean NOT NULL, revoked boolean NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS kg_ledger (
  key text PRIMARY KEY, limit_usd double precision, spent_usd double precision NOT NULL DEFAULT 0);
`

type PGState struct {
	db   *sql.DB
	lock *sql.Conn // соединение, на котором держится блокировка единственного экземпляра
	done chan struct{}
}

// OpenPGState подключается, создаёт таблицы и ждёт блокировку единственного экземпляра (до отмены ctx).
// onLost вызывается из фоновой горутины, если соединение с блокировкой потеряно.
func OpenPGState(ctx context.Context, dsn string, onWait func(), onLost func(error)) (*PGState, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetConnMaxIdleTime(5 * time.Minute)
	fail := func(err error) (*PGState, error) { db.Close(); return nil, err }
	conn, err := db.Conn(ctx)
	if err != nil {
		return fail(err)
	}
	for waited := false; ; {
		var got bool
		if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, int64(pgLockKey)).Scan(&got); err != nil {
			return fail(err)
		}
		if got {
			break
		}
		if !waited && onWait != nil {
			onWait()
		}
		waited = true
		select {
		case <-ctx.Done():
			return fail(fmt.Errorf("блокировка единственного экземпляра занята другим keyguard: %w", ctx.Err()))
		case <-time.After(time.Second):
		}
	}
	if _, err := db.ExecContext(ctx, pgSchema); err != nil {
		return fail(err)
	}
	p := &PGState{db: db, lock: conn, done: make(chan struct{})}
	every := lockCheckEvery // читается один раз здесь: тесты меняют интервал, горутина его больше не трогает
	go func() {             // блокировка живёт, пока живо соединение: проверяем его и поднимаем тревогу при потере
		for {
			select {
			case <-p.done:
				return
			case <-time.After(every):
			}
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			var held bool
			err := conn.QueryRowContext(c, `SELECT count(*) > 0 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted`).Scan(&held)
			cancel()
			if err == nil && !held {
				err = errors.New("блокировка единственного экземпляра больше не удерживается")
			}
			if err != nil {
				select {
				case <-p.done: // закрыли сами
				default:
					if onLost != nil {
						onLost(err)
					}
				}
				return
			}
		}
	}()
	return p, nil
}

// Ping — для /readyz: без базы keyguard не может записать ни nonce, ни расход.
func (p *PGState) Ping(ctx context.Context) error { return p.db.PingContext(ctx) }

func (p *PGState) Close() error {
	close(p.done)
	p.lock.Close()
	return p.db.Close()
}

func ctx5() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func pubBytes(k *ecdsa.PublicKey) ([]byte, error) {
	e, err := k.ECDH()
	if err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

func pubParse(b []byte) (*ecdsa.PublicKey, error) {
	if _, err := ecdh.P256().NewPublicKey(b); err != nil { // проверка: несжатая точка на кривой
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(b[1:33]), Y: new(big.Int).SetBytes(b[33:65])}, nil
}

func (p *PGState) Load(ctx context.Context) (*Snapshot, error) {
	s := &Snapshot{Limits: map[string]float64{}, Spent: map[string]float64{}}
	rows, err := p.db.QueryContext(ctx, `SELECT id, usr, session_pub, confirm_pub, revoked, pending, name, key_storage, csr, cert_pem, attested FROM kg_devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		d := &Device{}
		var sp, cp []byte
		if err := rows.Scan(&d.ID, &d.User, &sp, &cp, &d.Revoked, &d.Pending, &d.Name, &d.KeyStorage, &d.CSR, &d.CertPEM, &d.Attested); err != nil {
			return nil, err
		}
		// Запись с испорченным ключом не «теряется» молча: без неё отозванное устройство исчезло бы из реестра,
		// а его id можно было бы зарегистрировать заново.
		if d.SessionPub, err = pubParse(sp); err != nil {
			return nil, fmt.Errorf("устройство %s: ключ сессии: %w", d.ID, err)
		}
		if d.ConfirmPub, err = pubParse(cp); err != nil {
			return nil, fmt.Errorf("устройство %s: ключ подтверждения: %w", d.ID, err)
		}
		s.Devices = append(s.Devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	gr, err := p.db.QueryContext(ctx, `SELECT id, space, chat, proposal, provider, model, sponsor, limit_usd, per_member_usd_day,
		until_at, key_until_at, members, active, revoked FROM kg_grants`)
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	for gr.Next() {
		g := &Grant{}
		var members []byte
		if err := gr.Scan(&g.ID, &g.Space, &g.Chat, &g.Proposal, &g.Provider, &g.Model, &g.Sponsor, &g.LimitUSD, &g.PerMemberUSDDay,
			&g.Until, &g.KeyUntil, &members, &g.Active, &g.Revoked); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(members, &g.Members); err != nil {
			return nil, fmt.Errorf("разрешение %s: участники: %w", g.ID, err)
		}
		g.Until, g.KeyUntil = g.Until.UTC(), g.KeyUntil.UTC()
		s.Grants = append(s.Grants, g)
	}
	if err := gr.Err(); err != nil {
		return nil, err
	}
	lr, err := p.db.QueryContext(ctx, `SELECT key, limit_usd, spent_usd FROM kg_ledger`)
	if err != nil {
		return nil, err
	}
	defer lr.Close()
	for lr.Next() {
		var k string
		var lim sql.NullFloat64
		var spent float64
		if err := lr.Scan(&k, &lim, &spent); err != nil {
			return nil, err
		}
		if lim.Valid {
			s.Limits[k] = lim.Float64
		}
		s.Spent[k] = spent
	}
	return s, lr.Err()
}

func (p *PGState) SaveDevice(d *Device) error {
	sp, err := pubBytes(d.SessionPub)
	if err != nil {
		return err
	}
	cp, err := pubBytes(d.ConfirmPub)
	if err != nil {
		return err
	}
	ctx, cancel := ctx5()
	defer cancel()
	_, err = p.db.ExecContext(ctx, `INSERT INTO kg_devices (id, usr, session_pub, confirm_pub, revoked, pending, name, key_storage, csr, cert_pem, attested)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (id) DO UPDATE SET usr=$2, session_pub=$3, confirm_pub=$4, revoked=$5, pending=$6, name=$7,
		  key_storage=$8, csr=$9, cert_pem=$10, attested=$11, updated_at=now()`,
		d.ID, d.User, sp, cp, d.Revoked, d.Pending, d.Name, d.KeyStorage, d.CSR, d.CertPEM, d.Attested)
	return err
}

func (p *PGState) UseNonce(scope, nonce string, at time.Time) (bool, error) {
	ctx, cancel := ctx5()
	defer cancel()
	r, err := p.db.ExecContext(ctx, `INSERT INTO kg_nonces (scope, nonce, used_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, scope, nonce, at.UTC())
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (p *PGState) PruneNonces(before time.Time) error {
	ctx, cancel := ctx5()
	defer cancel()
	_, err := p.db.ExecContext(ctx, `DELETE FROM kg_nonces WHERE used_at < $1`, before.UTC())
	return err
}

func (p *PGState) SaveGrant(g *Grant) error {
	members, _ := json.Marshal(append([]string{}, g.Members...))
	ctx, cancel := ctx5()
	defer cancel()
	_, err := p.db.ExecContext(ctx, `INSERT INTO kg_grants (id, space, chat, proposal, provider, model, sponsor, limit_usd,
		  per_member_usd_day, until_at, key_until_at, members, active, revoked)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (id) DO UPDATE SET active=$13, revoked=$14, updated_at=now()`,
		g.ID, g.Space, g.Chat, g.Proposal, g.Provider, g.Model, g.Sponsor, g.LimitUSD, g.PerMemberUSDDay,
		g.Until.UTC(), g.KeyUntil.UTC(), string(members), g.Active, g.Revoked)
	return err
}

func (p *PGState) SetLimit(key string, usd float64, once bool) error {
	q := `INSERT INTO kg_ledger (key, limit_usd) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET limit_usd = $2`
	if once {
		q += ` WHERE kg_ledger.limit_usd IS NULL`
	}
	ctx, cancel := ctx5()
	defer cancel()
	_, err := p.db.ExecContext(ctx, q, key, usd)
	return err
}

func (p *PGState) AddSpent(keys []string, usd float64) error {
	ctx, cancel := ctx5()
	defer cancel()
	_, err := p.db.ExecContext(ctx, `INSERT INTO kg_ledger (key, spent_usd) SELECT k, $2 FROM unnest($1::text[]) AS k
		ON CONFLICT (key) DO UPDATE SET spent_usd = kg_ledger.spent_usd + $2`, pq.Array(keys), usd)
	return err
}
