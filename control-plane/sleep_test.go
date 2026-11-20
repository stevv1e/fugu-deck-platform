package controlplane

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSpaceSleepAndWake(t *testing.T) {
	st := newSpaceStand(t)
	st.s.Cfg.SleepAfter = time.Hour
	st.s.act.started = st.now
	busy, busyErr := false, error(nil)
	st.s.AgentHealth = func(context.Context, string) (AgentHealth, error) { return AgentHealth{Busy: busy}, busyErr }
	st.req("POST", "/v1/space", "", nil)
	set := func(f func(*SpaceInfo)) { s := st.sp.m["anna"]; f(&s); st.sp.m["anna"] = s }
	set(func(s *SpaceInfo) { s.Phase, s.Namespace = "Ready", "deck-u-anna" })
	pass := func(after time.Duration) bool {
		st.now = st.now.Add(after)
		st.s.SleepIdle(context.Background())
		return st.sp.m["anna"].Suspended
	}

	if pass(59 * time.Minute) {
		t.Fatal("усыплено раньше срока")
	}
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 200 {
		t.Fatalf("запрос в пространство: %d %s", w.Code, w.Body)
	}
	if pass(59 * time.Minute) {
		t.Fatal("запрос в пространство не сбросил отсчёт")
	}
	busy = true
	if pass(2 * time.Hour) {
		t.Fatal("усыплено посреди работы агента")
	}
	busy = false
	if pass(59 * time.Minute) {
		t.Fatal("работа агента не сбросила отсчёт")
	}
	busyErr = errors.New("агент не отвечает")
	if pass(2 * time.Hour) {
		t.Fatal("усыплено, хотя неизвестно, занят ли агент")
	}
	busyErr = nil
	// Не готовое пространство (запускается, удаляется) не усыпляем.
	set(func(s *SpaceInfo) { s.Phase = "Pending" })
	if pass(time.Hour) {
		t.Fatal("усыплено пространство, которое ещё запускается")
	}
	set(func(s *SpaceInfo) { s.Phase = "Ready" })
	if !pass(time.Minute) {
		t.Fatal("простаивающее пространство не усыплено")
	}

	// Флаг стоит, оператор ещё не убрал под (фаза Ready): для приложения пространство уже спит.
	if w := st.req("GET", "/v1/space", "", nil); !strings.Contains(w.Body.String(), `"phase":"Sleeping"`) {
		t.Fatalf("состояние спящего: %s", w.Body)
	}
	if !st.sp.m["anna"].Suspended {
		t.Fatal("просмотр состояния разбудил пространство")
	}
	set(func(s *SpaceInfo) { s.Phase = "Sleeping" })
	seen := len(st.seen)
	w := st.req("GET", "/s/anna/api/projects", "", nil)
	if w.Code != 503 || w.Header().Get("Retry-After") == "" || !strings.Contains(w.Body.String(), "просыпается") {
		t.Fatalf("запрос в спящее пространство: %d %s", w.Code, w.Body)
	}
	if st.sp.m["anna"].Suspended || len(st.seen) != seen {
		t.Fatal("запрос должен разбудить пространство и не уйти агенту, которого ещё нет")
	}
	// Оператор ещё не обновил фазу: повтор не ошибка и не будит второй раз; сразу после пробуждения не усыпляем.
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 503 {
		t.Fatalf("повтор, пока агент запускается: %d", w.Code)
	}
	if pass(30 * time.Minute) {
		t.Fatal("только что разбуженное пространство усыплено снова")
	}
	set(func(s *SpaceInfo) { s.Phase = "Ready" })
	if w := st.req("GET", "/s/anna/api/projects", "", nil); w.Code != 200 {
		t.Fatalf("после пробуждения: %d %s", w.Code, w.Body)
	}

	// Кнопка «Открыть пространство» (POST /v1/space) тоже будит.
	if !pass(2 * time.Hour) {
		t.Fatal("не усыплено повторно")
	}
	set(func(s *SpaceInfo) { s.Phase = "Sleeping" })
	if w := st.req("POST", "/v1/space", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"phase":"Pending"`) || st.sp.m["anna"].Suspended {
		t.Fatalf("POST /v1/space не разбудил: %d %s", w.Code, w.Body)
	}

	// Чужой пользователь чужое пространство не будит (для него оно выглядит несуществующим).
	set(func(s *SpaceInfo) { s.Suspended, s.Phase = true, "Sleeping" })
	bobTok := st.token(map[string]any{"preferred_username": "bob"})
	w = st.req("GET", "/s/anna/api/projects", "", func(r *http.Request) {
		r.Header.Set("Authorization", "DPoP "+bobTok)
		r.Header.Set("DPoP", st.proof(st.device, "GET", "https://api.deck.test/s/anna/api/projects", bobTok, nil))
	})
	if w.Code != 404 || !st.sp.m["anna"].Suspended {
		t.Fatalf("чужой запрос: %d, suspended=%v", w.Code, st.sp.m["anna"].Suspended)
	}
}

func TestSleepDisabled(t *testing.T) {
	st := newSpaceStand(t)
	st.req("POST", "/v1/space", "", nil)
	s := st.sp.m["anna"]
	s.Phase, s.Namespace = "Ready", "deck-u-anna"
	st.sp.m["anna"] = s
	st.now = st.now.Add(1000 * time.Hour)
	st.s.SleepIdle(context.Background())
	if st.sp.m["anna"].Suspended {
		t.Fatal("сон выключен (SleepAfter = 0), а пространство усыплено")
	}
}

// Задание по расписанию: перед сном control-plane запоминает, когда будить, и будит заранее.
func TestSpaceScheduledWake(t *testing.T) {
	st := newSpaceStand(t)
	st.s.Cfg.SleepAfter = time.Hour
	st.s.act.started = st.now
	var next time.Time
	st.s.AgentHealth = func(context.Context, string) (AgentHealth, error) { return AgentHealth{NextWake: next}, nil }
	st.req("POST", "/v1/space", "", nil)
	set := func(f func(*SpaceInfo)) { s := st.sp.m["anna"]; f(&s); st.sp.m["anna"] = s }
	set(func(s *SpaceInfo) { s.Phase, s.Namespace = "Ready", "deck-u-anna" })
	pass := func(after time.Duration) SpaceInfo {
		st.now = st.now.Add(after)
		st.s.SleepIdle(context.Background())
		return st.sp.m["anna"]
	}

	next = st.now.Add(61*time.Minute + 2*time.Minute)
	if sp := pass(61 * time.Minute); sp.Suspended {
		t.Fatal("усыплено за пару минут до задания")
	}
	next = st.now.Add(61*time.Minute + 5*time.Hour)
	sp := pass(61 * time.Minute)
	if !sp.Suspended || !sp.WakeAt.Equal(next) {
		t.Fatalf("сон без записи времени пробуждения: %+v", sp)
	}
	set(func(s *SpaceInfo) { s.Phase = "Sleeping" })
	if sp := pass(4*time.Hour + 50*time.Minute); !sp.Suspended {
		t.Fatal("разбужено слишком рано")
	}
	sp = pass(9 * time.Minute) // за минуту до задания
	if sp.Suspended || !sp.WakeAt.IsZero() {
		t.Fatalf("к заданию не разбужено: %+v", sp)
	}

	// Заданий нет — время пробуждения не ставится; спящее без него не будится.
	set(func(s *SpaceInfo) { s.Phase = "Ready" })
	next = time.Time{}
	sp = pass(61 * time.Minute)
	if !sp.Suspended || !sp.WakeAt.IsZero() {
		t.Fatalf("сон без расписания: %+v", sp)
	}
	set(func(s *SpaceInfo) { s.Phase = "Sleeping" })
	if sp := pass(48 * time.Hour); !sp.Suspended {
		t.Fatal("разбужено без расписания")
	}
	// Пространство ждёт удаления — к заданию не будим.
	set(func(s *SpaceInfo) { s.WakeAt, s.DeleteRequested = st.now, true })
	if sp := pass(time.Minute); !sp.Suspended {
		t.Fatal("разбужено пространство, которое удаляется")
	}
}
