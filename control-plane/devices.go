package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// Устройства и приглашения из приложения. control-plane здесь ничего не решает сам: список ведёт keyguard, а
// подтвердить, отозвать устройство или выпустить приглашение можно только действием, подписанным на телефоне
// ключом подтверждения (биометрия). Подпись проверяет keyguard — взломанный control-plane подделать её не может.

func (s *Server) kgJSON(w http.ResponseWriter, r *http.Request, path string, body []byte) (int, []byte, bool) {
	status, resp, err := s.KG.Post(r.Context(), path, body)
	if err != nil {
		s.Log.Printf("event=keyguard.unreachable path=%s err=%q", path, err.Error())
		fail(w, http.StatusBadGateway, "keyguard недоступен")
		return 0, nil, false
	}
	return status, resp, true
}

func readSmall(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		fail(w, http.StatusRequestEntityTooLarge, "тело слишком большое")
		return nil, false
	}
	return body, true
}

func relay(w http.ResponseWriter, status int, resp []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(resp)
}

func (s *Server) registerDevices(m *http.ServeMux) {
	// Свои устройства; администратору keyguard отдаёт устройства всех — ему подтверждать первые устройства приглашённых.
	m.HandleFunc("/v1/devices", s.api(http.MethodGet, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		q, _ := json.Marshal(map[string]string{"user": id.User})
		status, resp, ok := s.kgJSON(w, r, "/v1/devices/list", q)
		if !ok {
			return
		}
		if status != http.StatusOK {
			relay(w, status, resp)
			return
		}
		var out map[string]any
		if json.Unmarshal(resp, &out) != nil {
			fail(w, http.StatusBadGateway, "keyguard ответил не тем")
			return
		}
		out["user"], out["device_id"] = id.User, id.DeviceID // приложение помечает «это устройство»
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(out)
	}))
	for _, kind := range []string{"confirm", "revoke"} {
		kind := kind
		m.HandleFunc("/v1/devices/"+kind, s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
			body, ok := readSmall(w, r)
			if !ok {
				return
			}
			status, resp, ok := s.kgJSON(w, r, "/v1/devices/"+kind, body)
			if !ok {
				return
			}
			s.Log.Printf("event=device.%s user=%s device=%s status=%d", kind, id.User, id.DeviceID, status)
			relay(w, status, resp)
		}))
	}
	// Приглашение: подписанное действие invite_create. keyguard проверяет подпись и правило «другого пользователя
	// приглашает только администратор»; ник берётся из подписанного действия, а не из запроса.
	m.HandleFunc("/v1/invites", s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, ok := readSmall(w, r)
		if !ok {
			return
		}
		status, resp, ok := s.kgJSON(w, r, "/v1/actions/verify", body)
		if !ok {
			return
		}
		if status != http.StatusOK {
			s.Log.Printf("event=invite.denied user=%s device=%s status=%d", id.User, id.DeviceID, status)
			relay(w, status, resp)
			return
		}
		var v struct {
			Action struct {
				Type string `json:"type"`
				User string `json:"user"`
			} `json:"action"`
			User     string `json:"user"`
			DeviceID string `json:"device_id"`
		}
		// Подписать должен тот, кто вошёл: чужое подписанное действие, принесённое в свой сеанс, не годится.
		if json.Unmarshal(resp, &v) != nil || v.Action.Type != "invite_create" || v.User != id.User || v.DeviceID != id.DeviceID {
			fail(w, http.StatusForbidden, "действие подписано не этим устройством")
			return
		}
		s.dropLostPasskeys(r.Context(), v.Action.User)
		link, exp, err := s.NewInvite(r.Context(), v.Action.User, id.User)
		if errors.Is(err, ErrBadNick) {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		if err != nil {
			s.Log.Printf("event=invite.failed nick=%s err=%q", v.Action.User, err.Error())
			fail(w, http.StatusBadGateway, "не удалось выпустить приглашение")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{"nick": v.Action.User, "link": link, "expires": exp.UTC().Format(time.RFC3339)})
	}))
}

// dropLostPasskeys — перед приглашением пользователю без действующих устройств: его passkey остались на потерянном
// телефоне, и вход по новому приглашению просил бы их. Есть действующее устройство (или keyguard не ответил) —
// ничего не трогаем: passkey нужен тому устройству.
func (s *Server) dropLostPasskeys(ctx context.Context, nick string) {
	q, _ := json.Marshal(map[string]string{"user": nick})
	status, resp, err := s.KG.Post(ctx, "/v1/devices/list", q)
	var list struct {
		Devices []struct {
			User   string `json:"user"`
			Status string `json:"status"`
		} `json:"devices"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(resp, &list) != nil {
		s.Log.Printf("event=invite.passkeys_kept nick=%s reason=%q", nick, "keyguard не ответил")
		return
	}
	for _, d := range list.Devices {
		if d.User == nick && d.Status == "active" {
			return
		}
	}
	n, err := s.Users.RemovePasskeys(ctx, nick)
	if err != nil {
		s.Log.Printf("event=invite.passkeys_failed nick=%s err=%q", nick, err.Error())
		return
	}
	if n > 0 {
		s.Log.Printf("event=invite.passkeys_removed nick=%s count=%d", nick, n)
	}
}
