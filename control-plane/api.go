package controlplane

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

// apiHost — имя хоста api.<домен>. Обработчики API отвечают только на нём: порт 8080 общий с join.<домен>,
// а там mTLS нет, и заголовок с сертификатом устройства мог бы прийти от клиента.
func (s *Server) apiHost() string {
	u, err := url.Parse(s.Cfg.APIURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// api оборачивает обработчик API приложения: только свой хост, только опознанное устройство.
func (s *Server) api(method string, h func(w http.ResponseWriter, r *http.Request, id *Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.apiHost() {
			fail(w, http.StatusNotFound, "не найдено")
			return
		}
		if r.Method != method {
			fail(w, http.StatusMethodNotAllowed, "только "+method)
			return
		}
		id, err := s.Authenticate(r, s.Cfg.APIURL+r.URL.Path)
		if err != nil {
			s.Log.Printf("event=api.denied path=%s reason=%q", r.URL.Path, err.Error())
			fail(w, http.StatusUnauthorized, err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		s.touchUser(r.Context(), id.User)
		h(w, r, id)
	}
}

// apiAny — то же без ограничения метода (его проверяет сам обработчик или пространство).
func (s *Server) apiAny(h func(w http.ResponseWriter, r *http.Request, id *Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.apiHost() {
			fail(w, http.StatusNotFound, "не найдено")
			return
		}
		id, err := s.Authenticate(r, s.Cfg.APIURL+r.URL.Path)
		if err != nil {
			s.Log.Printf("event=api.denied path=%s reason=%q", r.URL.Path, err.Error())
			fail(w, http.StatusUnauthorized, err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		s.touchUser(r.Context(), id.User)
		h(w, r, id)
	}
}

func (s *Server) registerAPI(m *http.ServeMux) {
	m.HandleFunc("/v1/me", s.api(http.MethodGet, func(w http.ResponseWriter, _ *http.Request, id *Identity) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{"user": id.User, "device_id": id.DeviceID})
	}))
	// Ключ API: телефон шифрует его для keyguard (HPKE) и подписывает действие key_put. control-plane видит только
	// шифротекст и передаёт его как есть — расшифровать или подменить не может (подпись покрывает хеш шифротекста).
	m.HandleFunc("/v1/keys", s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			fail(w, http.StatusRequestEntityTooLarge, "тело слишком большое")
			return
		}
		status, resp, err := s.KG.Post(r.Context(), "/v1/keys", body)
		if err != nil {
			s.Log.Printf("event=keyguard.unreachable path=/v1/keys err=%q", err.Error())
			fail(w, http.StatusBadGateway, "keyguard недоступен")
			return
		}
		s.Log.Printf("event=key.put user=%s device=%s status=%d", id.User, id.DeviceID, status)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		w.Write(resp)
	}))
	// Свежая сборка приложения (DECK_APP_LATEST, DECK_APP_URL): приложение показывает «доступна новая версия».
	m.HandleFunc("/v1/app", s.api(http.MethodGet, func(w http.ResponseWriter, _ *http.Request, _ *Identity) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{"latest": s.Cfg.AppLatest, "url": s.Cfg.AppURL})
	}))
	// Удаление ключа и месячный лимит расходов — подписанные действия (key_delete, spend_limit): чей ключ и чей
	// лимит, keyguard определяет по подписавшему устройству; control-plane передаёт подпись как есть.
	m.HandleFunc("/v1/keys/delete", s.api(http.MethodPost, s.kgForward("/v1/keys/delete", "key.delete")))
	m.HandleFunc("/v1/limits", s.api(http.MethodPost, s.kgForward("/v1/limits", "limit.set")))
	// MCP-серверы владельца (keyguard, mcp.go): добавить (mcp_put, токен — HPKE), удалить (mcp_delete) — подписанные
	// действия идут в keyguard как есть; список — без токенов.
	m.HandleFunc("/v1/mcp", s.api(http.MethodPost, s.kgForwardN("/v1/mcp", "mcp.put", 64<<10)))
	m.HandleFunc("/v1/mcp/delete", s.api(http.MethodPost, s.kgForward("/v1/mcp/delete", "mcp.delete")))
	m.HandleFunc("/v1/mcp/list", s.api(http.MethodGet, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, _ := json.Marshal(map[string]string{"user": id.User})
		s.kgReply(w, r, "/v1/mcp/list", body)
	}))
	// Домены для агента (keyguard, egress.go): список задаёт подписанное действие egress_set целиком.
	m.HandleFunc("/v1/egress", s.api(http.MethodPost, s.kgForward("/v1/egress", "egress.set")))
	m.HandleFunc("/v1/egress/list", s.api(http.MethodGet, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, _ := json.Marshal(map[string]string{"user": id.User})
		s.kgReply(w, r, "/v1/egress/list", body)
	}))
	// Какие ключи заданы (без самих ключей), расход за месяц и лимит.
	m.HandleFunc("/v1/keys/status", s.api(http.MethodGet, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, _ := json.Marshal(map[string]string{"user": id.User})
		s.kgReply(w, r, "/v1/keys/status", body)
	}))
}

// kgForward — тело запроса (подписанное действие) уходит в keyguard без изменений; ответ — как есть.
func (s *Server) kgForward(path, event string) func(w http.ResponseWriter, r *http.Request, id *Identity) {
	return s.kgForwardN(path, event, 16<<10)
}

func (s *Server) kgForwardN(path, event string, limit int64) func(w http.ResponseWriter, r *http.Request, id *Identity) {
	return func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		if err != nil {
			fail(w, http.StatusRequestEntityTooLarge, "тело слишком большое")
			return
		}
		if status := s.kgReply(w, r, path, body); status != 0 {
			s.Log.Printf("event=%s user=%s device=%s status=%d", event, id.User, id.DeviceID, status)
		}
	}
}

func (s *Server) kgReply(w http.ResponseWriter, r *http.Request, path string, body []byte) int {
	status, resp, err := s.KG.Post(r.Context(), path, body)
	if err != nil {
		s.Log.Printf("event=keyguard.unreachable path=%s err=%q", path, err.Error())
		fail(w, http.StatusBadGateway, "keyguard недоступен")
		return 0
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(resp)
	return status
}
