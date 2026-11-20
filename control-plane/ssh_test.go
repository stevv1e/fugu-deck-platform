package controlplane

import (
	"context"
	"strings"
	"testing"
)

// fakeGW — ssh-gateway: запоминает, что ему передали.
type fakeGW struct {
	calls  []string
	bodies []string
}

func (f *fakeGW) Post(_ context.Context, path string, body []byte) (int, []byte, error) {
	f.calls, f.bodies = append(f.calls, path), append(f.bodies, string(body))
	return 200, []byte(`{"ok":true}`), nil
}

func TestSSHRelay(t *testing.T) {
	a := newAuthStand(t)
	// шлюз не настроен — этих адресов нет вовсе
	if w := a.req("GET", "/v1/ssh", "", nil); w.Code != 404 {
		t.Fatalf("без шлюза: %d", w.Code)
	}
	a = newAuthStand(t)
	gw := &fakeGW{}
	a.s.SSH = gw
	if w := a.req("GET", "/v1/ssh", "", nil); w.Code != 200 || gw.calls[0] != "/v1/state" || gw.bodies[0] != `{"space":"u-anna","user":"anna"}` {
		t.Fatalf("состояние: %d %v %v", w.Code, gw.calls, gw.bodies)
	}
	jws := func(typ, space, dev string) string {
		return `{"jws":"` + fakeJWS(map[string]any{"type": typ, "space": space, "device_id": dev, "server": "prod-1"}) + `"}`
	}
	good := jws("server_add", "u-anna", "d-device1")
	if w := a.req("POST", "/v1/ssh/servers", good, nil); w.Code != 200 || gw.calls[1] != "/servers" && gw.calls[1] != "/v1/servers" {
		t.Fatalf("сервер: %d %v", w.Code, gw.calls)
	}
	if gw.calls[1] != "/v1/servers" || !strings.Contains(gw.bodies[1], `"jws":"eyJ`) {
		t.Fatalf("подпись должна уйти шлюзу как есть по /v1/servers: %v %v", gw.calls[1], gw.bodies[1])
	}
	if w := a.req("POST", "/v1/ssh/rights", jws("agent_rights", "u-anna", "d-device1"), nil); w.Code != 200 || gw.calls[2] != "/v1/rights" {
		t.Fatalf("права: %d %v", w.Code, gw.calls)
	}
	if w := a.req("POST", "/v1/ssh/servers/remove", `{"server":"prod-1","space":"u-bob","user":"bob"}`, nil); w.Code != 403 || len(gw.calls) != 3 {
		t.Fatalf("удаление в чужом пространстве: %d", w.Code)
	}
	if w := a.req("POST", "/v1/ssh/servers/remove", `{"server":"prod-1","user":"bob"}`, nil); w.Code != 200 ||
		gw.bodies[3] != `{"server":"prod-1","space":"u-anna","user":"anna"}` {
		t.Fatalf("удаление: пространство и пользователь берутся из входа, а не из запроса: %v", gw.bodies[3])
	}
	if w := a.req("POST", "/v1/ssh/pause", `{"paused":true}`, nil); w.Code != 200 || gw.calls[4] != "/v1/pause" || gw.bodies[4] != `{"paused":true,"space":"u-anna","user":"anna"}` {
		t.Fatalf("остановка: %d %v", w.Code, gw.bodies)
	}
	if w := a.req("GET", "/v1/ssh/journal", "", nil); w.Code != 200 || gw.calls[5] != "/v1/journal" || !strings.Contains(gw.bodies[5], `"space":"u-anna"`) {
		t.Fatalf("журнал: %d %v", w.Code, gw.calls)
	}
	if w := a.req("GET", "/v1/ssh?space=t-notmine01", "", nil); w.Code != 403 {
		t.Fatalf("общее пространство, где не владелец: %d", w.Code)
	}
	n := len(gw.calls)
	for name, w := range map[string]int{
		"чужое пространство":           a.req("POST", "/v1/ssh/servers", jws("server_add", "u-bob", "d-device1"), nil).Code,
		"общее пространство":           a.req("POST", "/v1/ssh/servers", jws("server_add", "t-shop000001", "d-device1"), nil).Code,
		"действие другого типа":        a.req("POST", "/v1/ssh/servers", jws("agent_rights", "u-anna", "d-device1"), nil).Code,
		"подписано другим устройством": a.req("POST", "/v1/ssh/rights", jws("agent_rights", "u-anna", "d-other"), nil).Code,
		"команда через control-plane":  a.req("POST", "/v1/ssh/exec", `{"command":"id"}`, nil).Code,
		"не подписано":                 a.req("POST", "/v1/ssh/servers", `{"jws":"x"}`, nil).Code,
	} {
		if w == 200 {
			t.Errorf("%s: принято", name)
		}
	}
	if len(gw.calls) != n {
		t.Fatalf("отклонённое дошло до шлюза: %v", gw.calls[n:])
	}
}
