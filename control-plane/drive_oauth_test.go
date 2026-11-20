package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDriveOAuthCallbackStoresCodeInKeyguard(t *testing.T) {
	st := newStand()
	state := "state-1234567890abcdef"
	if err := st.s.Store.PutDriveState(state, DriveState{Nick: "anna", Verifier: "verifier-1234567890", Expires: st.now.Add(10 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/v1/drive/oauth/callback?state="+state+"&code=oauth-code-123", nil)
	w := httptest.NewRecorder()
	st.s.PublicHandler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if len(st.kg.calls) != 1 || st.kg.calls[0] != "/v1/drive/oauth/exchange" {
		t.Fatalf("вызовы keyguard: %v", st.kg.calls)
	}
	var body map[string]string
	if json.Unmarshal(st.kg.bodies[0], &body) != nil || body["user"] != "anna" || body["code"] != "oauth-code-123" || body["verifier"] != "verifier-1234567890" {
		t.Fatalf("неверный exchange: %v", body)
	}
	got, _ := st.s.Store.DriveState(state)
	if !got.Used || !got.Done {
		t.Fatalf("состояние не завершено: %+v", got)
	}
}

func TestDriveOAuthCallbackRejectsReplay(t *testing.T) {
	st := newStand()
	state := "state-1234567890abcdef"
	st.s.Store.PutDriveState(state, DriveState{Nick: "anna", Verifier: "verifier-1234567890", Expires: st.now.Add(-time.Second)})
	r := httptest.NewRequest("GET", "/v1/drive/oauth/callback?state="+state+"&code=oauth-code-123", nil)
	w := httptest.NewRecorder()
	st.s.PublicHandler().ServeHTTP(w, r)
	if w.Code != 403 || len(st.kg.calls) != 0 {
		t.Fatalf("истёкший state принят: %d", w.Code)
	}
}
