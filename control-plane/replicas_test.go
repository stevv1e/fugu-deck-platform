package controlplane

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// Две реплики на одном хранилище: повтор DPoP отклоняется и на другой реплике, обращение через одну видно сну другой.
func TestReplicasShareState(t *testing.T) {
	a := newAuthStand(t)
	b := newAuthStand(t)
	b.s.Store = a.s.Store // общее хранилище (в кластере — Postgres)
	b.kc, b.jwks = a.kc, a.jwks
	b.s.Keys = a.s.Keys
	b.device, b.cert = a.device, a.cert
	tok := a.token(nil)
	proof := a.proof(a.device, "GET", "https://api.deck.test/v1/me", tok, nil)
	set := func(r *http.Request) { r.Header.Set("Authorization", "DPoP "+tok); r.Header.Set("DPoP", proof) }
	if w := a.req("GET", "/v1/me", "", set); w.Code != 200 {
		t.Fatalf("первая реплика: %d %s", w.Code, w.Body)
	}
	if w := b.req("GET", "/v1/me", "", set); w.Code != 401 {
		t.Fatalf("тот же DPoP на второй реплике принят: %d", w.Code)
	}

	// активность: реплика A публикует обращение, сон реплики B его учитывает
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.s.RunActivity(ctx)
	for i := 0; i < 100; i++ {
		a.s.act.mu.Lock()
		ready := a.s.act.pub != nil
		a.s.act.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.s.act.touch("u-anna", a.now)
	var seen time.Time
	for i := 0; i < 100 && seen.IsZero(); i++ {
		seen, _ = b.s.Store.SpaceActivity("u-anna")
		time.Sleep(10 * time.Millisecond)
	}
	if !seen.Equal(a.now) {
		t.Fatalf("обращение через A не дошло до общего хранилища: %v", seen)
	}
	if !a.s.Store.Leader("sleeper") {
		t.Fatal("одна реплика (MemStore) всегда ведущая")
	}
}
