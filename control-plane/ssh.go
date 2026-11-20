package controlplane

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Серверы пользователя и права агента на них. Хранит и проверяет всё ssh-gateway; control-plane только передаёт:
// подписанные на телефоне действия server_add и agent_rights — как есть (подпись проверяет keyguard по просьбе шлюза),
// а список серверов — для экрана приложения. Выполнять команды control-plane не может: шлюз принимает их только от
// агента пространства.

func (s *Server) sshJSON(w http.ResponseWriter, r *http.Request, path string, body any) {
	raw, _ := json.Marshal(body)
	status, resp, err := s.SSH.Post(r.Context(), path, raw)
	if err != nil {
		s.Log.Printf("event=ssh_gateway.unreachable path=%s err=%q", path, err.Error())
		fail(w, http.StatusBadGateway, "шлюз серверов недоступен")
		return
	}
	relay(w, status, resp)
}

// sshSpace — о каком пространстве запрос: личное (team пусто) или общее, где пользователь — владелец (серверы общего
// пространства настраивает владелец). Решает всё равно шлюз — он сам узнаёт владельца из объекта Space.
func (s *Server) sshSpace(w http.ResponseWriter, id *Identity, team string) (string, bool) {
	if team == "" || team == "u-"+id.User {
		return "u-" + id.User, true
	}
	if acc, ok := s.access(id, team); ok && acc.Owner == id.User && strings.HasPrefix(team, "t-") {
		return team, true
	}
	fail(w, http.StatusForbidden, "серверы общего пространства настраивает его владелец")
	return "", false
}

func (s *Server) registerSSH(m *http.ServeMux) {
	if s.SSH == nil {
		return
	}
	// Серверы и права пространства, ключ CA и имя входа агента — чтобы настроить сервер. ?space=t-… — общее.
	m.HandleFunc("/v1/ssh", s.api(http.MethodGet, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		if sp, ok := s.sshSpace(w, id, r.URL.Query().Get("space")); ok {
			s.sshJSON(w, r, "/v1/state", map[string]string{"space": sp, "user": id.User})
		}
	}))
	// Журнал команд агента на серверах (30 дней).
	m.HandleFunc("/v1/ssh/journal", s.api(http.MethodGet, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		if sp, ok := s.sshSpace(w, id, r.URL.Query().Get("space")); ok {
			s.sshJSON(w, r, "/v1/journal", map[string]any{"space": sp, "user": id.User, "limit": 200})
		}
	}))
	// «Остановить агента на серверах» / «Возобновить». Остановка — уменьшение прав, подписи не требует.
	m.HandleFunc("/v1/ssh/pause", s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, ok := readSmall(w, r)
		if !ok {
			return
		}
		var q struct {
			Space  string `json:"space"`
			Paused bool   `json:"paused"`
		}
		if json.Unmarshal(body, &q) != nil {
			fail(w, http.StatusBadRequest, "json")
			return
		}
		if sp, ok := s.sshSpace(w, id, q.Space); ok {
			s.Log.Printf("event=ssh.pause user=%s space=%s paused=%v", id.User, sp, q.Paused)
			s.sshJSON(w, r, "/v1/pause", map[string]any{"space": sp, "user": id.User, "paused": q.Paused})
		}
	}))
	for path, typ := range map[string]string{"/v1/ssh/servers": "server_add", "/v1/ssh/rights": "agent_rights"} {
		path, typ := path, typ
		m.HandleFunc(path, s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
			body, ok := readSmall(w, r)
			if !ok {
				return
			}
			var q struct {
				JWS string `json:"jws"`
			}
			var a struct {
				Type, Space string
				DeviceID    string `json:"device_id"`
			}
			if json.Unmarshal(body, &q) != nil || !jwsRe.MatchString(q.JWS) {
				fail(w, http.StatusBadRequest, "нужно подписанное действие "+typ)
				return
			}
			payload, err := b64.DecodeString(strings.Split(q.JWS, ".")[1])
			// Заведомо негодное отсекаем сразу, чтобы человек увидел причину; решает всё равно шлюз.
			if err != nil || json.Unmarshal(payload, &a) != nil || a.Type != typ || a.DeviceID != id.DeviceID {
				fail(w, http.StatusForbidden, "действие не о вашем пространстве или подписано не этим устройством")
				return
			}
			if _, ok := s.sshSpace(w, id, a.Space); !ok {
				return
			}
			s.Log.Printf("event=ssh.%s user=%s device=%s", typ, id.User, id.DeviceID)
			s.sshJSON(w, r, "/v1"+strings.TrimPrefix(path, "/v1/ssh"), map[string]string{"jws": q.JWS})
		}))
	}
	m.HandleFunc("/v1/ssh/servers/remove", s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, ok := readSmall(w, r)
		if !ok {
			return
		}
		var q struct {
			Server string `json:"server"`
			Space  string `json:"space"`
		}
		if json.Unmarshal(body, &q) != nil || q.Server == "" {
			fail(w, http.StatusBadRequest, "не назван сервер")
			return
		}
		sp, ok := s.sshSpace(w, id, q.Space)
		if !ok {
			return
		}
		s.Log.Printf("event=ssh.server_remove user=%s device=%s space=%s server=%s", id.User, id.DeviceID, sp, q.Server)
		s.sshJSON(w, r, "/v1/servers/remove", map[string]string{"space": sp, "server": q.Server, "user": id.User})
	}))
}
