package keyguard

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"
)

// Личные ключи и расходы: удаление ключа (key_delete), что задано и сколько потрачено, месячный лимит (spend_limit).
// Вызывает только control-plane; чей ключ и чей лимит — определяет устройство, подписавшее действие.

// capKey — месячный лимит пользователя (настройка, не бюджет: в запросах не участвует). Отрицательное — без лимита.
func capKey(user string) string { return "cap:user:" + user }

// monthKey — расход пользователя за календарный месяц (UTC). Лимит месяца ставится при первом запросе месяца.
func monthKey(user string, t time.Time) string {
	return "user:" + user + ":" + t.UTC().Format("2006-01")
}

// noMonthCap — «лимита нет» для бюджета месяца, где лимит уже был поставлен (ledger лимиты не удаляет).
const noMonthCap = 1e9

func (s *Server) monthCap(user string) (float64, bool) {
	v, ok := s.Ledger.Limit(capKey(user))
	return v, ok && v >= 0
}

// applyMonthCap — лимит месяца из настройки, если он ещё не стоит (новый месяц начинается с нуля).
func (s *Server) applyMonthCap(user string, now time.Time) error {
	if c, ok := s.monthCap(user); ok {
		return s.Ledger.SetLimitOnce(monthKey(user, now), c)
	}
	return nil
}

func (s *Server) cpBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Method != http.MethodPost {
		fail(w, 405, "POST")
		return nil, false
	}
	if c, err := s.caller(r); err != nil || c != s.ControlPlane {
		fail(w, 403, "только control-plane")
		return nil, false
	}
	return s.readBody(w, r)
}

func (s *Server) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	body, ok := s.cpBody(w, r)
	if !ok {
		return
	}
	var sa SignedAction
	if json.Unmarshal(body, &sa) != nil {
		fail(w, 400, "json")
		return
	}
	a, dev, err := s.Verifier.Verify(sa, "key_delete")
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	user, prov := dev.User, s_(a, "provider")
	if s.Providers[prov] == nil || !safeSeg(user) {
		fail(w, 400, "провайдер/пользователь")
		return
	}
	if err := s.Store.Delete(r.Context(), user, prov); err != nil {
		s.Log.Printf("event=key.delete user=%s provider=%s result=store_error err=%q", uid(user), prov, err.Error())
		fail(w, 500, "хранилище")
		return
	}
	s.Log.Printf("event=key.delete user=%s provider=%s result=ok", uid(user), prov)
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// handleKeyStatus — какие ключи заданы (без самих ключей), расход за месяц и лимит. user называет control-plane:
// он опознал устройство; узнать чужое «задан ли ключ» он мог бы и так, а сами ключи отсюда не выходят.
func (s *Server) handleKeyStatus(w http.ResponseWriter, r *http.Request) {
	body, ok := s.cpBody(w, r)
	if !ok {
		return
	}
	var req struct {
		User string `json:"user"`
	}
	if json.Unmarshal(body, &req) != nil || !safeSeg(req.User) {
		fail(w, 400, "user")
		return
	}
	set := []string{}
	for _, p := range allProviders {
		if s.Providers[p] == nil {
			continue
		}
		_, err := s.Store.Get(r.Context(), req.User, p)
		switch {
		case err == nil:
			set = append(set, p)
		case !errors.Is(err, ErrNoKey):
			s.Log.Printf("event=key.status result=store_error err=%q", err.Error())
			fail(w, 503, "хранилище ключей недоступно")
			return
		}
	}
	now := s.Now()
	out := map[string]any{"providers": set, "month": now.UTC().Format("2006-01"),
		"spent_usd_month": round2(s.Ledger.Spent(monthKey(req.User, now))), "spent_usd_total": round2(s.Ledger.Spent("user:" + req.User)),
		"limit_usd_month": nil}
	if c, ok := s.monthCap(req.User); ok {
		out["limit_usd_month"] = c
	}
	json.NewEncoder(w).Encode(out)
}

// handleKeysMine — личному пространству: у каких провайдеров моделей у его владельца есть ключ. Только имена
// провайдеров: ни ключей, ни расходов пространство не видит. Без этого пространство считало «ключ есть» у всех
// провайдеров (вместо ключа у него токен keyguard), и приложение показывало модели, которые не ответят.
func (s *Server) handleKeysMine(w http.ResponseWriter, r *http.Request) {
	c, err := s.caller(r)
	if err != nil {
		fail(w, 401, "не опознан")
		return
	}
	if !strings.HasPrefix(c.Namespace, "deck-u-") {
		fail(w, 403, "только личные пространства: в общих платит спонсор по разрешению")
		return
	}
	user := strings.TrimPrefix(c.Namespace, "deck-u-")
	set := []string{}
	for _, p := range allProviders {
		if s.Providers[p] == nil || s.Providers[p].Kind == "git" {
			continue
		}
		_, err := s.Store.Get(r.Context(), user, p)
		switch {
		case err == nil:
			set = append(set, p)
		case !errors.Is(err, ErrNoKey):
			s.Log.Printf("event=key.mine result=store_error err=%q", err.Error())
			fail(w, 503, "хранилище ключей недоступно")
			return
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"providers": set})
}

func round2(x float64) float64 { return math.Round(x*10000) / 10000 }

func (s *Server) handleSpendLimit(w http.ResponseWriter, r *http.Request) {
	body, ok := s.cpBody(w, r)
	if !ok {
		return
	}
	var sa SignedAction
	if json.Unmarshal(body, &sa) != nil {
		fail(w, 400, "json")
		return
	}
	a, dev, err := s.Verifier.Verify(sa, "spend_limit")
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	user := dev.User
	if !safeSeg(user) {
		fail(w, 400, "пользователь")
		return
	}
	limit := -1.0
	if a["limit_usd_month"] != nil {
		v, ok := usd(a, "limit_usd_month")
		if !ok {
			fail(w, 400, "limit_usd_month")
			return
		}
		limit = v
	}
	mk := monthKey(user, s.Now())
	// Сначала настройка, потом текущий месяц: упадём между ними — следующий запрос к модели поставит лимит месяца сам,
	// если он ещё не стоял; стоявший прежде лимит месяца исправит повтор действия.
	if err := s.Ledger.SetLimit(capKey(user), limit); err != nil {
		s.stateFail(w, "ledger.limit", err)
		return
	}
	cur := limit
	if limit < 0 {
		cur = noMonthCap
	}
	if _, had := s.Ledger.Limit(mk); had || limit >= 0 {
		if err := s.Ledger.SetLimit(mk, cur); err != nil {
			s.stateFail(w, "ledger.limit", err)
			return
		}
	}
	s.Log.Printf("event=limit.set user=%s limit_usd_month=%.2f", uid(user), limit)
	out := map[string]any{"limit_usd_month": nil, "spent_usd_month": round2(s.Ledger.Spent(mk))}
	if limit >= 0 {
		out["limit_usd_month"] = limit
	}
	json.NewEncoder(w).Encode(out)
}
