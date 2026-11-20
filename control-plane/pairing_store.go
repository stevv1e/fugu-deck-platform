package controlplane

import (
	"database/sql"
	"errors"
	"time"
)

func (p *PGStore) PutPairing(v Pairing) error {
	_, err := p.DB.Exec(`INSERT INTO cp_pairings
		(id, code, nick, name, session_jkt, confirm_jkt, secret_hash, expires)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, v.ID, v.Code, v.Nick, v.Name, v.SessionJKT, v.ConfirmJKT, v.SecretHash, v.Expires)
	return err
}

func scanPairing(row interface{ Scan(...any) error }) (Pairing, error) {
	var v Pairing
	var approvedBy sql.NullString
	var approvedAt sql.NullTime
	err := row.Scan(&v.ID, &v.Code, &v.Nick, &v.Name, &v.SessionJKT, &v.ConfirmJKT, &v.SecretHash, &v.Expires, &approvedBy, &approvedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Pairing{}, ErrNotFound
	}
	v.ApprovedBy, v.Approved = approvedBy.String, approvedAt.Valid
	return v, err
}

const pairingColumns = `id, code, nick, name, session_jkt, confirm_jkt, secret_hash, expires, approved_by, approved_at`

func (p *PGStore) Pairing(id string) (Pairing, error) {
	return scanPairing(p.DB.QueryRow(`SELECT `+pairingColumns+` FROM cp_pairings WHERE id=$1`, id))
}

func (p *PGStore) PairingByCode(code string) (Pairing, error) {
	return scanPairing(p.DB.QueryRow(`SELECT `+pairingColumns+` FROM cp_pairings WHERE code=$1`, code))
}

func (p *PGStore) ApprovePairing(id, by string, now time.Time) (Pairing, error) {
	r, err := p.DB.Exec(`UPDATE cp_pairings SET approved_by=$2, approved_at=$3
		WHERE id=$1 AND approved_at IS NULL AND expires>$3`, id, by, now)
	if err != nil {
		return Pairing{}, err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return Pairing{}, ErrNotFound
	}
	return p.Pairing(id)
}

func (m *MemStore) PutPairing(v Pairing) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pairings == nil {
		m.pairings = map[string]Pairing{}
	}
	for _, old := range m.pairings {
		if old.Code == v.Code {
			return errors.New("код уже используется")
		}
	}
	m.pairings[v.ID] = v
	return nil
}

func (m *MemStore) Pairing(id string) (Pairing, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.pairings[id]
	if !ok {
		return Pairing{}, ErrNotFound
	}
	return v, nil
}

func (m *MemStore) PairingByCode(code string) (Pairing, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.pairings {
		if v.Code == code {
			return v, nil
		}
	}
	return Pairing{}, ErrNotFound
}

func (m *MemStore) ApprovePairing(id, by string, now time.Time) (Pairing, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.pairings[id]
	if !ok || v.Approved || !now.Before(v.Expires) {
		return Pairing{}, ErrNotFound
	}
	v.ApprovedBy, v.Approved = by, true
	m.pairings[id] = v
	return v, nil
}
