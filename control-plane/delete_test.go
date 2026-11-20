package controlplane

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fakeJWS(payload map[string]any) string {
	p, _ := json.Marshal(payload)
	return "eyJhbGciOiJFUzI1NiJ9." + b64.EncodeToString(p) + ".c2ln"
}

func TestSpaceDeleteRequest(t *testing.T) {
	st := newSpaceStand(t)
	good := fakeJWS(map[string]any{"type": "space_delete", "space": "u-anna", "device_id": "d-device1", "nonce": "n", "ts": 1})
	body := func(jws string) string { b, _ := json.Marshal(map[string]string{"jws": jws}); return string(b) }
	if w := st.req("POST", "/v1/space/delete", body(good), nil); w.Code != 404 {
		t.Fatalf("нет пространства: %d", w.Code)
	}
	st.req("POST", "/v1/space", "", nil)
	set := func(f func(*SpaceInfo)) { s := st.sp.m["anna"]; f(&s); st.sp.m["anna"] = s }
	set(func(s *SpaceInfo) { s.Phase, s.Namespace = "Ready", "deck-u-anna" })

	// Заведомо негодное до Space не доходит.
	for name, jws := range map[string]string{
		"не JWS":             "мусор",
		"другое действие":    fakeJWS(map[string]any{"type": "tool_approve", "space": "u-anna", "device_id": "d-device1"}),
		"чужое пространство": fakeJWS(map[string]any{"type": "space_delete", "space": "u-bob", "device_id": "d-device1"}),
		"другое устройство":  fakeJWS(map[string]any{"type": "space_delete", "space": "u-anna", "device_id": "d-other"}),
	} {
		if w := st.req("POST", "/v1/space/delete", body(jws), nil); w.Code == 200 || st.sp.m["anna"].DeleteRequested {
			t.Errorf("%s: запрос принят (%d)", name, w.Code)
		}
	}

	w := st.req("POST", "/v1/space/delete", body(good), nil)
	if w.Code != 200 || st.sp.deleteSig != good || !strings.Contains(w.Body.String(), `"delete_requested":true`) || strings.Contains(w.Body.String(), "delete_at") {
		t.Fatalf("запрос удаления: %d %s", w.Code, w.Body)
	}
	// Оператор отклонил подпись: приложение видит причину, пространство работает, можно запросить снова.
	set(func(s *SpaceInfo) { s.DeleteError = "подпись не принята: повтор" })
	if w := st.req("GET", "/v1/space", "", nil); !strings.Contains(w.Body.String(), `"delete_error":"подпись не принята: повтор"`) || !strings.Contains(w.Body.String(), `"phase":"Ready"`) {
		t.Fatalf("отклонённый запрос: %s", w.Body)
	}
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 200 {
		t.Fatalf("пространство с отклонённым запросом должно работать: %d", w.Code)
	}
	if w := st.req("POST", "/v1/space/delete", body(good), nil); w.Code != 200 {
		t.Fatalf("повторный запрос после отказа: %d %s", w.Code, w.Body)
	}
	// Оператор принял: пространство остановлено и недоступно, срок виден, сон и пробуждение его не трогают.
	set(func(s *SpaceInfo) { s.Phase, s.DeleteAt, s.DeleteError = "Deleting", "2026-10-12T12:00:00Z", "" })
	if w := st.req("GET", "/v1/space", "", nil); !strings.Contains(w.Body.String(), `"delete_at":"2026-10-12T12:00:00Z"`) || !strings.Contains(w.Body.String(), `"phase":"Deleting"`) {
		t.Fatalf("принятый запрос: %s", w.Body)
	}
	seen := len(st.seen)
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 409 || w.Header().Get("Retry-After") != "" || len(st.seen) != seen {
		t.Fatalf("запрос в удаляемое пространство: %d", w.Code)
	}
	if w := st.req("POST", "/v1/space", "", nil); !strings.Contains(w.Body.String(), `"phase":"Deleting"`) || !st.sp.m["anna"].DeleteRequested {
		t.Fatalf("«открыть» не должно отменять удаление: %s", w.Body)
	}
	if w := st.req("POST", "/v1/space/delete", body(good), nil); w.Code != 409 {
		t.Fatalf("повторный запрос при принятом: %d", w.Code)
	}

	// Отмена.
	w = st.req("POST", "/v1/space/restore", "", nil)
	if w.Code != 200 || st.sp.m["anna"].DeleteRequested || st.sp.deleteSig != "" || strings.Contains(w.Body.String(), "delete_") {
		t.Fatalf("отмена: %d %s", w.Code, w.Body)
	}
	if w := st.req("POST", "/v1/space/restore", "", nil); w.Code != 200 {
		t.Fatalf("повторная отмена: %d", w.Code)
	}
	if w := st.req("GET", "/v1/space/delete", "", nil); w.Code != 405 {
		t.Fatalf("GET: %d", w.Code)
	}
}

func TestAccountDeleteRequest(t *testing.T) {
	st := newSpaceStand(t)
	good := fakeJWS(map[string]any{"type": "account_delete", "user": "anna", "device_id": "d-device1", "nonce": "n", "ts": 1})
	body := func(jws string) string { b, _ := json.Marshal(map[string]string{"jws": jws}); return string(b) }
	for name, jws := range map[string]string{
		"удаление пространства вместо аккаунта": fakeJWS(map[string]any{"type": "space_delete", "space": "u-anna", "device_id": "d-device1"}),
		"чужой аккаунт":     fakeJWS(map[string]any{"type": "account_delete", "user": "bob", "device_id": "d-device1"}),
		"другое устройство": fakeJWS(map[string]any{"type": "account_delete", "user": "anna", "device_id": "d-other"}),
	} {
		if w := st.req("POST", "/v1/account/delete", body(jws), nil); w.Code == 200 {
			t.Errorf("%s: принято", name)
		}
	}
	// Пространства ещё нет — создаётся, чтобы удаление шло одним путём через оператора.
	w := st.req("POST", "/v1/account/delete", body(good), nil)
	if w.Code != 200 || st.sp.deleteSig != good || !st.sp.m["anna"].DeleteRequested {
		t.Fatalf("запрос удаления аккаунта: %d %s", w.Code, w.Body)
	}
	set := func(f func(*SpaceInfo)) { s := st.sp.m["anna"]; f(&s); st.sp.m["anna"] = s }
	set(func(s *SpaceInfo) {
		s.Phase, s.DeleteAt, s.DeleteKind = "Deleting", st.now.Add(24*time.Hour).Format(time.RFC3339), "account"
	})
	if w := st.req("GET", "/v1/space", "", nil); !strings.Contains(w.Body.String(), `"delete_account":true`) {
		t.Fatalf("приложение должно видеть, что удаляется аккаунт: %s", w.Body)
	}
	// До срока учётная запись не трогается.
	st.s.FinishAccountDeletions(context.Background())
	if len(st.dir.deleted) != 0 {
		t.Fatal("учётная запись удалена до срока")
	}
	// Отмена — keyguard забывает проверенную подпись.
	st.kg.resp = `{"ok":true}`
	n := len(st.kg.calls)
	if w := st.req("POST", "/v1/space/restore", "", nil); w.Code != 200 || st.sp.m["anna"].DeleteRequested {
		t.Fatalf("отмена: %d %s", w.Code, w.Body)
	}
	if len(st.kg.calls) != n+1 || st.kg.calls[n] != "/v1/account/cancel" || !strings.Contains(string(st.kg.bodies[n]), `"anna"`) {
		t.Fatalf("keyguard не узнал об отмене: %v", st.kg.calls)
	}
	// Срок вышел: учётная запись удаляется (повтор безвреден).
	st.req("POST", "/v1/account/delete", body(good), nil)
	set(func(s *SpaceInfo) {
		s.DeleteAt, s.DeleteKind = st.now.Add(-time.Minute).Format(time.RFC3339), "account"
	})
	st.s.FinishAccountDeletions(context.Background())
	if len(st.dir.deleted) != 1 || st.dir.deleted[0] != "anna" {
		t.Fatalf("учётная запись: %v", st.dir.deleted)
	}
}
