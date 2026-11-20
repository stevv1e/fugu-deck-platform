package controlplane

// Подключение Google Drive из приложения: браузер → Google → callback control-plane → keyguard.
// state и PKCE verifier одноразовые и живут 10 минут; refresh token получает только keyguard.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const driveScope = "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/drive.file"

func driveRandom() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *Server) registerDrive(m *http.ServeMux) {
	m.HandleFunc("/v1/drive/oauth/start", s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		if s.Cfg.DriveClientID == "" {
			fail(w, 503, "Google OAuth не настроен")
			return
		}
		state, err := driveRandom()
		if err != nil {
			fail(w, 500, "state")
			return
		}
		verifier, err := driveRandom()
		if err != nil {
			fail(w, 500, "PKCE")
			return
		}
		if err := s.Store.PutDriveState(state, DriveState{Nick: id.User, Verifier: verifier, Expires: s.now().Add(10 * time.Minute)}); err != nil {
			fail(w, 500, "не удалось сохранить состояние OAuth")
			return
		}
		challenge := sha256.Sum256([]byte(verifier))
		q := url.Values{"client_id": {s.Cfg.DriveClientID}, "redirect_uri": {s.Cfg.JoinURL + "/v1/drive/oauth/callback"},
			"response_type": {"code"}, "scope": {driveScope}, "state": {state}, "access_type": {"offline"},
			"prompt": {"consent"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"state": state, "url": "https://accounts.google.com/o/oauth2/v2/auth?" + q.Encode()})
	}))

	m.HandleFunc("/v1/drive/oauth/status", s.api(http.MethodGet, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		state := r.URL.Query().Get("state")
		value, err := s.Store.DriveState(state)
		if err != nil || value.Nick != id.User {
			fail(w, 404, "OAuth-сессия не найдена")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"connected": value.Done, "pending": value.Used && !value.Done, "expires": value.Expires})
	}))

	m.HandleFunc("/v1/drive/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			fail(w, 405, "GET")
			return
		}
		state := r.URL.Query().Get("state")
		if r.URL.Query().Get("error") != "" {
			driveCallback(w, 403, "Google отклонил подключение", false)
			return
		}
		value, err := s.Store.UseDriveState(state, s.now())
		if err != nil {
			driveCallback(w, 403, "OAuth-сессия недействительна или истекла", false)
			return
		}
		body, _ := json.Marshal(map[string]string{"user": value.Nick, "code": r.URL.Query().Get("code"), "verifier": value.Verifier})
		status, _, err := s.KG.Post(r.Context(), "/v1/drive/oauth/exchange", body)
		if err != nil || status != 200 {
			s.Log.Printf("event=drive.oauth.failed user=%s status=%d", value.Nick, status)
			driveCallback(w, 502, "Не удалось сохранить подключение. Вернитесь в приложение и попробуйте снова.", false)
			return
		}
		if err := s.Store.FinishDriveState(state); err != nil {
			driveCallback(w, 500, "Подключение сохранено, но статус не обновлён", false)
			return
		}
		s.Log.Printf("event=drive.oauth.connected user=%s", value.Nick)
		driveCallback(w, 200, "Google Drive подключён. Можно вернуться в Fugu Deck.", true)
	})
}

func driveCallback(w http.ResponseWriter, status int, text string, ok bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	link := ""
	if ok {
		link = `<p><a href="fugudeck://drive">Открыть Fugu Deck</a></p>`
	}
	fmt.Fprintf(w, `<!doctype html><html lang="ru"><meta name="viewport" content="width=device-width"><title>Fugu Deck</title><body style="font-family:system-ui;padding:32px;max-width:480px;margin:auto"><h2>Fugu Deck</h2><p>%s</p>%s</body></html>`, text, link)
}
