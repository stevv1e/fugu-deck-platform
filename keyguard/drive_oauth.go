package keyguard

// Обмен OAuth authorization code происходит в keyguard: control-plane видит код и PKCE verifier,
// но не refresh token. Токен сразу сохраняется в слот google_drive пользователя.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) handleDriveOAuthExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "POST")
		return
	}
	if c, err := s.caller(r); err != nil || c != s.ControlPlane {
		fail(w, 403, "только control-plane")
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var q struct {
		User     string `json:"user"`
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}
	if json.Unmarshal(body, &q) != nil || !safeSeg(q.User) || len(q.Code) < 8 || len(q.Code) > 4096 || len(q.Verifier) < 43 || len(q.Verifier) > 128 {
		fail(w, 400, "неверный OAuth exchange")
		return
	}
	p := s.Providers["google_drive"]
	if p == nil || p.OAuthClientID == "" || p.OAuthClientSecret == "" || p.OAuthRedirect == "" {
		fail(w, 503, "Google OAuth не настроен")
		return
	}
	form := url.Values{"client_id": {p.OAuthClientID}, "client_secret": {p.OAuthClientSecret}, "code": {q.Code},
		"code_verifier": {q.Verifier}, "redirect_uri": {p.OAuthRedirect}, "grant_type": {"authorization_code"}}
	req, _ := http.NewRequestWithContext(r.Context(), "POST", driveTokenURL(p), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.Upstream.Do(req)
	if err != nil {
		fail(w, 502, "Google OAuth недоступен")
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		RefreshToken string `json:"refresh_token"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(raw, &out) != nil || out.RefreshToken == "" {
		fail(w, 502, "Google не выдал refresh token; повторите подключение")
		return
	}
	if err := s.Store.Put(r.Context(), q.User, "google_drive", out.RefreshToken); err != nil {
		s.stateFail(w, "drive.oauth.store", err)
		return
	}
	s.Log.Printf("event=drive.oauth.stored user=%s", uid(q.User))
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}
