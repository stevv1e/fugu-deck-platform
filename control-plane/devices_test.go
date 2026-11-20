package controlplane

import (
	"net/http"
	"strings"
	"testing"
)

func TestDevicesAPI(t *testing.T) {
	a := newAuthStand(t)
	a.kg.resp = `{"devices":[{"id":"d-device1","user":"anna","name":"Pixel","status":"active"}],"admin":false}`
	w := a.req("GET", "/v1/devices", "", nil)
	if w.Code != 200 || a.kg.calls[0] != "/v1/devices/list" || string(a.kg.bodies[0]) != `{"user":"anna"}` {
		t.Fatalf("список: %d %s %v %s", w.Code, w.Body, a.kg.calls, a.kg.bodies)
	}
	for _, want := range []string{`"device_id":"d-device1"`, `"user":"anna"`, `"name":"Pixel"`, `"admin":false`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("в списке нет %s: %s", want, w.Body)
		}
	}
	// Подтверждение и отзыв: подписанное действие уходит в keyguard как есть, его ответ — приложению.
	for _, kind := range []string{"confirm", "revoke"} {
		a.kg.status, a.kg.resp = 200, `{"ok":true}`
		body := `{"jws":"x.y.z"}`
		w := a.req("POST", "/v1/devices/"+kind, body, nil)
		last := len(a.kg.calls) - 1
		if w.Code != 200 || a.kg.calls[last] != "/v1/devices/"+kind || string(a.kg.bodies[last]) != body {
			t.Fatalf("%s: %d %v", kind, w.Code, a.kg.calls)
		}
		a.kg.status, a.kg.resp = 403, `{"error":"подтверждать и отзывать чужие устройства может только администратор"}`
		if w := a.req("POST", "/v1/devices/"+kind, body, nil); w.Code != 403 || !strings.Contains(w.Body.String(), "администратор") {
			t.Fatalf("%s: отказ keyguard не передан: %d %s", kind, w.Code, w.Body)
		}
	}
	n := len(a.kg.calls)
	for name, w := range map[string]int{
		"список без DPoP":           a.req("GET", "/v1/devices", "", func(r *http.Request) { r.Header.Del("DPoP") }).Code,
		"отзыв без сертификата":     a.req("POST", "/v1/devices/revoke", "{}", func(r *http.Request) { r.Header.Del(certHeader) }).Code,
		"приглашение на хосте join": a.req("POST", "/v1/invites", "{}", func(r *http.Request) { r.Host = "join.deck.test" }).Code,
	} {
		if w == 200 {
			t.Errorf("%s: запрос принят", name)
		}
	}
	if len(a.kg.calls) != n {
		t.Fatal("неопознанный запрос дошёл до keyguard")
	}
}

func TestInviteFromApp(t *testing.T) {
	a := newAuthStand(t)
	verified := func(actionUser, by, device string) string {
		return `{"action":{"type":"invite_create","user":"` + actionUser + `"},"user":"` + by + `","device_id":"` + device + `"}`
	}
	a.kg.resp = verified("anna", "anna", "d-device1")
	w := a.req("POST", "/v1/invites", `{"jws":"x.y.z"}`, nil)
	if w.Code != 200 || a.kg.calls[0] != "/v1/actions/verify" || string(a.kg.bodies[0]) != `{"jws":"x.y.z"}` {
		t.Fatalf("приглашение: %d %s %v", w.Code, w.Body, a.kg.calls)
	}
	if !strings.Contains(w.Body.String(), `"nick":"anna"`) || !strings.Contains(w.Body.String(), "fugudeck://join?") || !strings.Contains(w.Body.String(), "invite=") {
		t.Fatalf("нет ссылки: %s", w.Body)
	}
	if len(a.dir.users) != 1 || a.dir.users[0] != "anna" {
		t.Fatalf("пользователь в Keycloak: %v", a.dir.users)
	}
	// Ник берётся из подписанного действия, а не из тела запроса.
	a.kg.resp = verified("dave", "anna", "d-device1")
	if w := a.req("POST", "/v1/invites", `{"jws":"x.y.z","nick":"mallory"}`, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"nick":"dave"`) {
		t.Fatalf("ник не из действия: %d %s", w.Code, w.Body)
	}
	users := len(a.dir.users)
	deny := map[string]func(){
		"keyguard отказал (не администратор)": func() {
			a.kg.status, a.kg.resp = 403, `{"error":"приглашать других пользователей может только администратор"}`
		},
		"действие подписал другой пользователь": func() { a.kg.status, a.kg.resp = 200, verified("anna", "bob", "d-device1") },
		"действие подписано другим устройством": func() { a.kg.status, a.kg.resp = 200, verified("anna", "anna", "d-other") },
		"keyguard проверил действие другого типа": func() {
			a.kg.status, a.kg.resp = 200, `{"action":{"type":"account_delete","user":"anna"},"user":"anna","device_id":"d-device1"}`
		},
		"недопустимый ник":            func() { a.kg.status, a.kg.resp = 200, verified("../x", "anna", "d-device1") },
		"ответ keyguard не разобрать": func() { a.kg.status, a.kg.resp = 200, `ok` },
	}
	for name, set := range deny {
		set()
		if w := a.req("POST", "/v1/invites", `{"jws":"x.y.z"}`, nil); w.Code == 200 || strings.Contains(w.Body.String(), "fugudeck://") {
			t.Errorf("%s: приглашение выпущено (%d %s)", name, w.Code, w.Body)
		}
	}
	if len(a.dir.users) != users {
		t.Fatalf("при отказе заведён пользователь: %v", a.dir.users)
	}
}

// Потерян единственный телефон: приглашение пользователю без действующих устройств удаляет его старые passkey.
func TestInviteLostPhone(t *testing.T) {
	a := newAuthStand(t)
	a.kg.byPath = map[string]string{
		"/v1/actions/verify": `{"action":{"type":"invite_create","user":"bob"},"user":"anna","device_id":"d-device1"}`,
	}
	invite := func(list string) {
		t.Helper()
		a.kg.byPath["/v1/devices/list"] = list
		if w := a.req("POST", "/v1/invites", `{"jws":"x.y.z"}`, nil); w.Code != 200 {
			t.Fatalf("приглашение: %d %s", w.Code, w.Body)
		}
	}
	invite(`{"devices":[{"user":"bob","status":"active"},{"user":"bob","status":"revoked"}]}`)
	if len(a.dir.passkeysRemoved) != 0 {
		t.Fatalf("L1 у Боба есть действующее устройство — passkey не трогаем: %v", a.dir.passkeysRemoved)
	}
	invite(`{"devices":[{"user":"bob","status":"revoked"},{"user":"anna","status":"active"}]}`)
	if len(a.dir.passkeysRemoved) != 1 || a.dir.passkeysRemoved[0] != "bob" {
		t.Fatalf("L2 у Боба только отозванные — его passkey удалены: %v", a.dir.passkeysRemoved)
	}
	invite(`не json`)
	if len(a.dir.passkeysRemoved) != 1 {
		t.Fatalf("L3 keyguard ответил непонятно — passkey не трогаем: %v", a.dir.passkeysRemoved)
	}
}
