package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// Сон пространств. Под агента занимает память ноды, даже когда человек неделю не открывал приложение.
// control-plane видит все обращения к пространству (они идут через него) и по неактивности ставит spec.suspended —
// space-operator убирает под (том с данными остаётся). Первое же обращение владельца снимает флаг; приложение
// получает 503 «просыпается» и повторяет запрос.
//
// Активность хранится в памяти: после перезапуска control-plane отсчёт для всех пространств начинается заново —
// пространство уснёт позже, но не раньше положенного.

type activity struct {
	mu       sync.Mutex
	started  time.Time
	last     map[string]time.Time
	inflight map[string]int
	// pub — сообщить другим репликам (общее хранилище, D73); nil — одна реплика. Не чаще раза в activityPub.
	pub       func(name string, at time.Time)
	published map[string]time.Time
}

const activityPub = 30 * time.Second

func (a *activity) touch(name string, now time.Time) {
	a.mu.Lock()
	if a.last == nil {
		a.last, a.inflight = map[string]time.Time{}, map[string]int{}
	}
	a.last[name] = now
	pub := a.pub
	if pub != nil {
		if a.published == nil {
			a.published = map[string]time.Time{}
		}
		if now.Sub(a.published[name]) < activityPub {
			pub = nil
		} else {
			a.published[name] = now
		}
	}
	a.mu.Unlock()
	if pub != nil {
		go pub(name, now)
	}
}

// busy — пространства с открытыми запросами в этой реплике (поток ответа модели — активность, пока открыт).
func (a *activity) busy() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for n, k := range a.inflight {
		if k > 0 {
			out = append(out, n)
		}
	}
	return out
}

// enter отмечает начало запроса к пространству; возвращённую функцию вызывают по его окончании. Открытый поток
// ответа модели — это активность всё время, пока он открыт.
func (a *activity) enter(name string, now func() time.Time) func() {
	a.touch(name, now())
	a.mu.Lock()
	a.inflight[name]++
	a.mu.Unlock()
	return func() {
		a.mu.Lock()
		a.inflight[name]--
		a.mu.Unlock()
		a.touch(name, now())
	}
}

// idleFor — сколько пространство без обращений; ok=false, пока есть незавершённые запросы.
func (a *activity) idleFor(name string, now time.Time) (time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inflight[name] > 0 {
		return 0, false
	}
	last, seen := a.last[name]
	if !seen || last.Before(a.started) {
		last = a.started
	}
	return now.Sub(last), true
}

// AgentHealth — что агент говорит о себе: идёт ли работа и когда ближайшее задание по расписанию.
type AgentHealth struct {
	Busy     bool
	NextWake time.Time // нуль — заданий по расписанию нет
}

// wakeLead — за сколько до задания будить пространство: оператору нужно время поднять под.
const wakeLead = 2 * time.Minute

// agentHealth спрашивает самого агента, идёт ли работа: задание продолжается и после того, как человек закрыл
// приложение, и усыпить пространство посреди него значило бы оборвать работу.
func (s *Server) agentHealth(ctx context.Context, namespace string) (AgentHealth, error) {
	if s.AgentHealth != nil {
		return s.AgentHealth(ctx, namespace)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.SpaceURL(namespace).String()+"/api/health", nil)
	if err != nil {
		return AgentHealth{}, err
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return AgentHealth{}, err
	}
	defer r.Body.Close()
	var h struct {
		Busy     bool     `json:"busy"`
		NextWake *float64 `json:"next_wake"` // unix-время ближайшего задания по расписанию
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&h) != nil {
		return AgentHealth{}, io.ErrUnexpectedEOF
	}
	out := AgentHealth{Busy: h.Busy}
	if h.NextWake != nil && *h.NextWake > 0 {
		out.NextWake = time.Unix(int64(*h.NextWake), 0).UTC()
	}
	return out, nil
}

// SleepIdle — один проход: усыпить готовые пространства, к которым не обращались дольше Cfg.SleepAfter.
func (s *Server) SleepIdle(ctx context.Context) {
	if s.Spaces == nil || s.Cfg.SleepAfter <= 0 {
		return
	}
	spaces, err := s.Spaces.List(ctx)
	if err != nil {
		s.Log.Printf("event=sleep.list_failed err=%q", err.Error())
		return
	}
	for _, sp := range spaces {
		if sp.Suspended {
			s.wakeScheduled(ctx, sp)
			continue
		}
		if sp.Phase != "Ready" {
			continue
		}
		idle, ok := s.act.idleFor(sp.Name, s.now())
		// обращения через другие реплики (и открытые в них потоки — по пульсу RunActivity)
		if t, err := s.Store.SpaceActivity(sp.Name); err == nil && !t.IsZero() && s.now().Sub(t) < idle {
			idle = s.now().Sub(t)
		}
		if !ok || idle < s.Cfg.SleepAfter {
			continue
		}
		h, err := s.agentHealth(ctx, sp.Namespace)
		if err != nil {
			// Не знаем, занят ли агент, — не трогаем: лучше лишний работающий под, чем оборванное задание.
			s.Log.Printf("event=sleep.busy_unknown space=%s err=%q", sp.Name, err.Error())
			continue
		}
		// Работа идёт или задание по расписанию совсем скоро — отсчёт заново: усыпить и тут же будить незачем.
		if h.Busy || (!h.NextWake.IsZero() && h.NextWake.Sub(s.now()) < 3*wakeLead) {
			s.act.touch(sp.Name, s.now())
			continue
		}
		// Когда будить — записываем до сна: не записалось — не усыпляем, иначе задание по расписанию пропало бы.
		if !h.NextWake.Equal(sp.WakeAt) {
			if err := s.Spaces.SetWakeAt(ctx, sp.Name, h.NextWake); err != nil {
				s.Log.Printf("event=sleep.wake_at_failed space=%s err=%q", sp.Name, err.Error())
				continue
			}
		}
		if err := s.Spaces.SetSuspended(ctx, sp.Name, true); err != nil {
			s.Log.Printf("event=sleep.failed space=%s err=%q", sp.Name, err.Error())
			continue
		}
		s.Log.Printf("event=space.sleep space=%s idle=%s wake_at=%s", sp.Name, idle.Round(time.Second), wakeText(h.NextWake))
	}
}

func wakeText(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}

// wakeScheduled будит спящее пространство к заданию по расписанию (заранее, на wakeLead).
func (s *Server) wakeScheduled(ctx context.Context, sp SpaceInfo) {
	if sp.WakeAt.IsZero() || sp.DeleteRequested || s.now().Before(sp.WakeAt.Add(-wakeLead)) {
		return
	}
	if err := s.wake(ctx, sp); err != nil {
		return
	}
	if err := s.Spaces.SetWakeAt(ctx, sp.Name, time.Time{}); err != nil {
		s.Log.Printf("event=wake.clear_failed space=%s err=%q", sp.Name, err.Error())
	}
	s.Log.Printf("event=space.wake_scheduled space=%s at=%s", sp.Name, sp.WakeAt.Format(time.RFC3339))
}

// RunSleeper — проходы SleepIdle с заданным шагом, пока не отменён контекст.
func (s *Server) RunSleeper(ctx context.Context, every time.Duration) {
	s.act.mu.Lock()
	s.act.started = s.now()
	s.act.mu.Unlock()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !s.Store.Leader("sleeper") { // при нескольких репликах — одна (D73)
				continue
			}
			s.SleepIdle(ctx)
			s.FinishAccountDeletions(ctx)
			s.CheckInactive(ctx)
		}
	}
}

// RunActivity — на каждой реплике: обращения к пространствам видны всем репликам (общее хранилище), а открытые
// потоки — пульсом раз в activityPub, пока открыты.
func (s *Server) RunActivity(ctx context.Context) {
	pub := func(name string, at time.Time) {
		if err := s.Store.TouchSpace(name, at); err != nil {
			s.Log.Printf("event=activity.store_failed space=%s err=%q", name, err.Error())
		}
	}
	s.act.mu.Lock()
	s.act.pub = pub
	s.act.mu.Unlock()
	t := time.NewTicker(activityPub)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, n := range s.act.busy() {
				pub(n, s.now())
			}
		}
	}
}

// asleep — пространство спит или засыпает (флаг уже стоит, а оператор ещё не убрал под).
func asleep(info SpaceInfo) bool { return info.Suspended || info.Phase == "Sleeping" }

// wake снимает флаг сна. Обращение владельца — уже активность: иначе следующий проход усыпил бы пространство снова.
func (s *Server) wake(ctx context.Context, info SpaceInfo) error {
	s.act.touch(info.Name, s.now())
	if !info.Suspended {
		return nil // флаг уже снят, оператор запускает агента
	}
	if err := s.Spaces.SetSuspended(ctx, info.Name, false); err != nil {
		s.Log.Printf("event=wake.failed space=%s err=%q", info.Name, err.Error())
		return err
	}
	s.Log.Printf("event=space.wake space=%s", info.Name)
	return nil
}
