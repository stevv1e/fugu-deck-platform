package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Отозванное устройство теряет доступ к api, не дожидаясь конца срока сертификата.
func TestRevokedDevice(t *testing.T) {
	a := newAuthStand(t)
	var list []string
	var fetchErr error
	calls := 0
	a.s.RevokedList = func(context.Context) ([]string, error) {
		calls++
		return list, fetchErr
	}
	if w := a.req("GET", "/v1/me", "", nil); w.Code != 200 {
		t.Fatalf("R1 действующее устройство: %d %s", w.Code, w.Body)
	}
	list = []string{"d-other", "d-device1"}
	if w := a.req("GET", "/v1/me", "", nil); w.Code != 200 || calls != 1 {
		t.Fatalf("R2 в пределах %s список не перечитывается: %d, запросов %d", revokedTTL, w.Code, calls)
	}
	a.now = a.now.Add(revokedTTL)
	if w := a.req("GET", "/v1/me", "", nil); w.Code != 401 || !strings.Contains(w.Body.String(), "отозвано") || calls != 2 {
		t.Fatalf("R3 после отзыва — 401: %d %s, запросов %d", w.Code, w.Body, calls)
	}
	n := len(a.kg.calls)
	if w := a.req("POST", "/v1/keys", `{"jws":"x.y.z","enc":"AA==","ct":"BB=="}`, nil); w.Code != 401 || len(a.kg.calls) != n {
		t.Fatalf("R4 отозванное устройство не доходит до keyguard: %d, вызовов %d→%d", w.Code, n, len(a.kg.calls))
	}
	a.now = a.now.Add(time.Minute)
	fetchErr = errors.New("keyguard недоступен")
	if w := a.req("GET", "/v1/me", "", nil); w.Code != 401 {
		t.Fatalf("R5 keyguard недоступен — действует последний список: %d", w.Code)
	}
	b := newAuthStand(t)
	b.s.RevokedList = func(context.Context) ([]string, error) { return nil, errors.New("нет связи") }
	if w := b.req("GET", "/v1/me", "", nil); w.Code != 200 {
		t.Fatalf("R6 списка ещё не было — устройство пускается: %d", w.Code)
	}
}
