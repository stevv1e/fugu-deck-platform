package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Удаление аккаунта. Телефон подписывает account_delete; control-plane кладёт подпись в запрос удаления личного
// пространства (как space_delete) — проверяет её и отсчитывает сутки на отмену space-operator. Когда срок вышел,
// оператор удаляет пространство с копиями и просит keyguard стереть ключи, устройства и разрешения; control-plane
// удаляет учётную запись в Keycloak и участие в чужих общих пространствах. Отмена — та же, что у пространства.

func (s *Server) registerAccount(m *http.ServeMux) {
	m.HandleFunc("/v1/account/delete", s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, ok := readSmall(w, r)
		if !ok {
			return
		}
		var q struct {
			JWS string `json:"jws"`
		}
		if json.Unmarshal(body, &q) != nil || !jwsRe.MatchString(q.JWS) || len(q.JWS) > 4096 {
			fail(w, http.StatusBadRequest, "нужно подписанное действие account_delete")
			return
		}
		var a struct {
			Type, User string
			DeviceID   string `json:"device_id"`
		}
		payload, err := b64.DecodeString(strings.Split(q.JWS, ".")[1])
		if err != nil || json.Unmarshal(payload, &a) != nil || a.Type != "account_delete" || a.User != id.User || a.DeviceID != id.DeviceID {
			fail(w, http.StatusForbidden, "действие не об удалении вашего аккаунта или подписано не этим устройством")
			return
		}
		info, err := s.Spaces.Get(r.Context(), id.User)
		if errors.Is(err, ErrNotFound) {
			// Пространства ещё нет: создаём его, чтобы удаление шло одним путём (оператор проверит подпись и сроки).
			_, pub, e := s.signer()
			if e == nil {
				e = s.Spaces.Ensure(r.Context(), id.User, id.User, pub)
			}
			if e == nil {
				info, err = s.Spaces.Get(r.Context(), id.User)
			} else {
				err = e
			}
		}
		if err != nil {
			s.Log.Printf("event=account.delete_failed user=%s err=%q", id.User, err.Error())
			fail(w, http.StatusBadGateway, "не удалось записать запрос удаления")
			return
		}
		if info.Owner != id.User {
			fail(w, http.StatusNotFound, "пространство не найдено")
			return
		}
		if info.DeleteRequested && info.DeleteAt != "" {
			fail(w, http.StatusConflict, "удаление уже запрошено — отмените его, чтобы запросить заново")
			return
		}
		if err := s.Spaces.RequestDelete(r.Context(), id.User, q.JWS, s.now()); err != nil {
			s.Log.Printf("event=account.delete_failed user=%s err=%q", id.User, err.Error())
			fail(w, http.StatusBadGateway, "не удалось записать запрос удаления")
			return
		}
		s.Log.Printf("event=account.delete_requested user=%s device=%s", id.User, id.DeviceID)
		info.DeleteRequested, info.DeleteAt, info.DeleteError = true, "", ""
		s.writeSpace(w, info, true)
	}))
}

// FinishAccountDeletions — для пространств, удаляемых вместе с аккаунтом, после срока отмены: учётная запись в
// Keycloak и участие в общих пространствах. Повторяется на каждом проходе, пока оператор не удалил Space: оба
// действия при повторе безвредны.
func (s *Server) FinishAccountDeletions(ctx context.Context) {
	if s.Spaces == nil || s.Users == nil {
		return
	}
	spaces, err := s.Spaces.List(ctx)
	if err != nil {
		return
	}
	for _, sp := range spaces {
		if (sp.DeleteKind != "account" && sp.DeleteKind != "inactive") || sp.DeleteAt == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339, sp.DeleteAt)
		if err != nil || s.now().Before(at) {
			continue
		}
		nick := sp.Owner
		if teams, err := s.Store.TeamsOf(nick); err == nil {
			for _, t := range teams {
				if t.Owner == nick {
					// Своё общее пространство — участникам: владельцем становится старший редактор (иначе — любой).
					if heir := s.heir(t.ID, nick); heir != "" {
						if err := s.doTransfer(ctx, t.ID, heir); err != nil {
							s.Log.Printf("event=account.team_transfer_failed team=%s err=%q", t.ID, err.Error())
							continue
						}
						s.Log.Printf("event=account.team_transferred team=%s to=%s", t.ID, heir)
					} else {
						continue // других участников нет: пространство остаётся (удалить его можно подписью владельца раньше)
					}
				}
				s.Store.SetMember(t.ID, nick, "", "account-delete")
			}
		}
		if err := s.Users.DeleteUser(ctx, nick); err != nil {
			s.Log.Printf("event=account.keycloak_delete_failed user=%s err=%q", nick, err.Error())
			continue
		}
		s.Log.Printf("event=account.keycloak_deleted user=%s", nick)
	}
}

// heir — кому передать общее пространство удаляемого владельца: первый по нику редактор, иначе первый читатель.
func (s *Server) heir(team, owner string) string {
	ms, err := s.Store.Members(team)
	if err != nil {
		return ""
	}
	best := ""
	for _, role := range []string{"editor", "reader"} {
		for _, m := range ms {
			if m.Nick != owner && m.Role == role && (best == "" || m.Nick < best) {
				best = m.Nick
			}
		}
		if best != "" {
			return best
		}
	}
	return ""
}

// ---------------- неактивные аккаунты ----------------

// seenThrottle — отметку входа пишем в базу не чаще раза в час на пользователя.
type seenThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// touchUser — приложение обратилось к api: человек активен. Снимает просьбу удалить аккаунт по неактивности.
func (s *Server) touchUser(ctx context.Context, nick string) {
	now := s.now()
	s.seen.mu.Lock()
	if s.seen.last == nil {
		s.seen.last = map[string]time.Time{}
	}
	fresh := now.Sub(s.seen.last[nick]) < time.Hour
	if !fresh {
		s.seen.last[nick] = now
	}
	s.seen.mu.Unlock()
	if fresh {
		return
	}
	if err := s.Store.Seen(nick, now); err != nil {
		s.Log.Printf("event=seen.failed user=%s err=%q", nick, err.Error())
	}
	if s.Spaces != nil {
		// и в сутки до удаления: оператор увидит снятую просьбу и отменит
		if info, err := s.Spaces.Get(ctx, nick); err == nil && info.InactiveDelete && info.DeleteKind != "account" {
			if err := s.Spaces.SetInactiveDelete(ctx, nick, false); err == nil {
				s.Log.Printf("event=inactive.cancelled user=%s", nick)
			}
		}
	}
}

// CheckInactive — напоминания за неделю и за день, затем просьба удалить аккаунт. Cfg.InactiveDays == 0 — выключено.
func (s *Server) CheckInactive(ctx context.Context) {
	days := s.Cfg.InactiveDays
	if days <= 0 || s.Spaces == nil {
		return
	}
	users, err := s.Store.SeenUsers()
	if err != nil {
		return
	}
	now := s.now()
	for _, u := range users {
		idle := now.Sub(u.Last)
		left := time.Duration(days)*24*time.Hour - idle
		switch {
		case left <= 0:
			if info, err := s.Spaces.Get(ctx, u.Nick); err == nil && !info.InactiveDelete && !info.DeleteRequested {
				if err := s.Spaces.SetInactiveDelete(ctx, u.Nick, true); err == nil {
					s.Log.Printf("event=inactive.requested user=%s last=%s", u.Nick, u.Last.Format(time.RFC3339))
				}
			}
		case left <= 24*time.Hour && u.Reminded != 1:
			s.notify(ctx, u.Nick, Notification{Title: "Аккаунт удалится завтра",
				Body: "Вы давно не открывали Fugu Deck. Откройте приложение, чтобы сохранить аккаунт и данные",
				Data: map[string]string{"kind": "inactive"}})
			s.Store.SetReminded(u.Nick, 1)
		case left <= 7*24*time.Hour && u.Reminded == 0:
			s.notify(ctx, u.Nick, Notification{Title: "Аккаунт удалится через неделю",
				Body: "Вы давно не открывали Fugu Deck. Откройте приложение, чтобы сохранить аккаунт и данные",
				Data: map[string]string{"kind": "inactive"}})
			s.Store.SetReminded(u.Nick, 7)
		}
	}
}
