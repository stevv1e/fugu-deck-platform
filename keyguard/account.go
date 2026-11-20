package keyguard

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Удаление аккаунта (account_delete). Подпись владельца проверяет space-operator (через /v1/actions/verify) и
// отсчитывает сутки, в которые удаление можно отменить; keyguard запоминает момент проверки. Когда пространство
// удалено, оператор просит стереть то, что хранит keyguard: ключи API, устройства, разрешения спонсора. keyguard
// соглашается, только если сам проверил подпись этого пользователя не меньше purgeDelay назад и её не отменили.

const purgeDelay = 23 * time.Hour

// inactiveAfter — стереть данные за неактивность keyguard согласен, только если сам не видел пользователя столько.
const inactiveAfter = 29 * 24 * time.Hour

// seenKey — когда keyguard последний раз видел пользователя (подпись его устройства, проверка устройства), unix-время.
func seenKey(user string) string { return "seen:" + user }

// markSeen — отметка активности, не чаще раза в час (запись в хранилище состояния).
func (s *Server) markSeen(user string) {
	if !safeSeg(user) {
		return
	}
	now := s.Now()
	if at, ok := s.Ledger.Limit(seenKey(user)); ok && now.Sub(time.Unix(int64(at), 0)) < time.Hour {
		return
	}
	if err := s.Ledger.SetLimit(seenKey(user), float64(now.Unix())); err != nil {
		s.Log.Printf("event=state.error op=seen err=%q", err.Error())
	}
}

// acctDelKey — когда проверена подпись account_delete (unix-время); -1 — отменено, -2 — данные стёрты.
func acctDelKey(user string) string { return "acctdel:" + user }

var operatorCaller = Caller{Namespace: "deck-system", ServiceAccount: "space-operator"}

func (s *Server) userBody(w http.ResponseWriter, r *http.Request, from Caller) (string, bool) {
	user, _, ok := s.userReason(w, r, from)
	return user, ok
}

func (s *Server) userReason(w http.ResponseWriter, r *http.Request, from Caller) (string, string, bool) {
	if r.Method != http.MethodPost {
		fail(w, 405, "POST")
		return "", "", false
	}
	if c, err := s.caller(r); err != nil || c != from {
		fail(w, 403, "не тот вызывающий")
		return "", "", false
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return "", "", false
	}
	var req struct {
		User   string `json:"user"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal(body, &req) != nil || !safeSeg(req.User) {
		fail(w, 400, "user")
		return "", "", false
	}
	return req.User, req.Reason, true
}

// handleAccountPurge — space-operator, после удаления пространства: стереть ключи, отозвать устройства и разрешения.
func (s *Server) handleAccountPurge(w http.ResponseWriter, r *http.Request) {
	user, reason, ok := s.userReason(w, r, operatorCaller)
	if !ok {
		return
	}
	at, marked := s.Ledger.Limit(acctDelKey(user))
	if marked && at == -2 {
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "already": true}) // повтор после обрыва
		return
	}
	if reason == "inactive" {
		// Подписи нет: стираем, только если сами не видели человека inactiveAfter. Сведений нет — отсчёт с этой минуты.
		seen, ok := s.Ledger.Limit(seenKey(user))
		if !ok {
			s.markSeen(user)
			fail(w, 403, "keyguard ещё не знает, когда пользователь был активен — отсчёт начат")
			return
		}
		if s.Now().Sub(time.Unix(int64(seen), 0)) < inactiveAfter {
			fail(w, 403, "пользователь был активен недавно (по данным keyguard)")
			return
		}
	} else {
		switch {
		case !marked || at < 0:
			fail(w, 403, "подпись удаления этого аккаунта не проверялась или отменена")
			return
		case s.Now().Sub(time.Unix(int64(at), 0)) < purgeDelay:
			fail(w, 403, "сутки на отмену удаления ещё не прошли")
			return
		}
	}
	keys := s.purgeKeys(r.Context(), user)
	if keys < 0 {
		fail(w, 503, "хранилище ключей недоступно, повторите позже")
		return
	}
	devs := 0
	for _, d := range s.Verifier.Devices.List(user) {
		if !d.Revoked {
			s.Verifier.Devices.Revoke(d.ID) // в памяти отзыв действует и при сбое базы
			devs++
		}
	}
	grants, err := s.Grants.RevokeSponsor(user)
	if err != nil {
		s.stateFail(w, "account.grants", err)
		return
	}
	if err := s.Ledger.SetLimit(acctDelKey(user), -2); err != nil {
		s.stateFail(w, "account.done", err)
		return
	}
	s.Log.Printf("event=account.purged user=%s reason=%s keys=%d devices=%d grants=%d", uid(user), reason, keys, devs, grants)
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "keys": keys, "devices": devs, "grants": grants})
}

// purgeKeys удаляет ключи всех провайдеров; -1 — хранилище не ответило.
func (s *Server) purgeKeys(ctx context.Context, user string) int {
	n := 0
	for p := range s.Providers {
		if _, err := s.Store.Get(ctx, user, p); err == nil {
			n++
		}
		if err := s.Store.Delete(ctx, user, p); err != nil {
			s.Log.Printf("event=account.purge_key user=%s provider=%s err=%q", uid(user), p, err.Error())
			return -1
		}
	}
	return n
}

// handleAccountCancel — control-plane: человек отменил удаление в отведённые сутки.
func (s *Server) handleAccountCancel(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userBody(w, r, s.ControlPlane)
	if !ok {
		return
	}
	if at, marked := s.Ledger.Limit(acctDelKey(user)); marked && at == -2 {
		fail(w, 409, "данные аккаунта уже стёрты")
		return
	}
	if err := s.Ledger.SetLimit(acctDelKey(user), -1); err != nil {
		s.stateFail(w, "account.cancel", err)
		return
	}
	s.Log.Printf("event=account.delete_cancelled user=%s", uid(user))
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
