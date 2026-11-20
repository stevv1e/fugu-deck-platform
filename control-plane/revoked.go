package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Отозванные устройства. Источник правды — keyguard (отзыв — подписанное действие); control-plane держит копию
// списка и обновляет её не реже revokedTTL, чтобы отозванный телефон терял доступ к api и пространствам сразу,
// а не когда истечёт его сертификат (720 ч). keyguard недоступен — действует последний полученный список;
// пока не получен ни один — пускаем (подписи отозванного устройства keyguard всё равно не примет).
const revokedTTL = 10 * time.Second

var errRevoked = errors.New("устройство отозвано")

type revokedList struct {
	mu  sync.Mutex
	ids map[string]bool
	at  time.Time
	ok  bool
}

// KeyguardRevoked — список с keyguard (POST /v1/devices/revoked).
func KeyguardRevoked(kg Keyguard) func(context.Context) ([]string, error) {
	return func(ctx context.Context) ([]string, error) {
		st, resp, err := kg.Post(ctx, "/v1/devices/revoked", []byte(`{}`))
		if err != nil {
			return nil, err
		}
		if st != 200 {
			return nil, fmt.Errorf("keyguard: %d", st)
		}
		var out struct {
			Revoked []string `json:"revoked"`
		}
		if err := json.Unmarshal(resp, &out); err != nil {
			return nil, err
		}
		return out.Revoked, nil
	}
}

// deviceRevoked — отозвано ли устройство (по копии списка; устаревшую копию сначала обновляет).
func (s *Server) deviceRevoked(ctx context.Context, id string) bool {
	if s.RevokedList == nil {
		return false
	}
	l := &s.revoked
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := s.now(); !l.ok || now.Sub(l.at) >= revokedTTL {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		ids, err := s.RevokedList(c)
		cancel()
		if err != nil {
			s.Log.Printf("event=revoked.refresh_failed have_list=%t err=%q", l.ok, err.Error())
		} else {
			m := make(map[string]bool, len(ids))
			for _, x := range ids {
				m[x] = true
			}
			l.ids, l.at, l.ok = m, now, true
		}
	}
	return l.ids[id]
}
