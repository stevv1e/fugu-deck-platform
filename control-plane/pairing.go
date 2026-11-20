package controlplane

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	pairCookie       = "deck_pair"
	pairStatusHeader = "X-Deck-Pair-Status"
	pairTTL          = 15 * time.Minute
)

var (
	pairIDRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	pairSecretRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	pairJKTRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	pairCodeRe   = regexp.MustCompile(`^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$`)
)

func pairRandom(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pairCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

func normalizePairCode(v string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(v), "-", ""), " ", ""))
}

func pairDeviceID(confirmJKT string) string { return "d-" + confirmJKT[:16] }

func (s *Server) validPair(id, secret, nick string) (Pairing, bool) {
	if !pairIDRe.MatchString(id) || !pairSecretRe.MatchString(secret) {
		return Pairing{}, false
	}
	p, err := s.Store.Pairing(id)
	if err != nil || p.Nick != nick || !s.now().Before(p.Expires) || !hmac.Equal([]byte(p.SecretHash), []byte(hashToken(secret))) {
		return Pairing{}, false
	}
	return p, true
}

func (s *Server) pairStatus(r *http.Request, nick string) string {
	c, err := r.Cookie(pairCookie)
	if err != nil || c.Value == "" {
		return "none"
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return "invalid"
	}
	p, ok := s.validPair(parts[0], parts[1], nick)
	if !ok {
		return "invalid"
	}
	if p.Approved {
		return "approved"
	}
	return "pending"
}

func pairPublic(p Pairing) map[string]any {
	return map[string]any{
		"id": p.ID, "code": p.Code, "user": p.Nick, "name": p.Name,
		"device_id": pairDeviceID(p.ConfirmJKT), "session_jkt": p.SessionJKT,
		"expires": p.Expires.UTC().Format(time.RFC3339), "approved": p.Approved,
	}
}

func (s *Server) registerPairing(m *http.ServeMux) {
	m.HandleFunc("/v1/pair/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fail(w, http.StatusMethodNotAllowed, "только POST")
			return
		}
		inv, _, err := s.lookup(r.Header.Get(inviteHeader))
		if err != nil || inv.Used {
			fail(w, http.StatusUnauthorized, "нужно действующее приглашение")
			return
		}
		body, ok := readSmall(w, r)
		if !ok {
			return
		}
		var q struct {
			Name       string `json:"name"`
			SessionJKT string `json:"session_jkt"`
			ConfirmJKT string `json:"confirm_jkt"`
		}
		if err := json.Unmarshal(body, &q); err != nil {
			fail(w, http.StatusBadRequest, "json")
			return
		}
		q.Name = strings.TrimSpace(q.Name)
		if q.Name == "" || len(q.Name) > 80 || !pairJKTRe.MatchString(q.SessionJKT) || !pairJKTRe.MatchString(q.ConfirmJKT) || q.SessionJKT == q.ConfirmJKT {
			fail(w, http.StatusBadRequest, "некорректные имя или ключи устройства")
			return
		}
		id, err := pairRandom(32)
		if err != nil {
			fail(w, http.StatusInternalServerError, "не удалось создать pairing")
			return
		}
		secret, err := pairRandom(32)
		if err != nil {
			fail(w, http.StatusInternalServerError, "не удалось создать pairing")
			return
		}
		expires := s.now().Add(pairTTL)
		if inv.Expires.Before(expires) {
			expires = inv.Expires
		}
		var p Pairing
		created := false
		for range 5 {
			code, err := pairCode()
			if err != nil {
				fail(w, http.StatusInternalServerError, "не удалось создать код")
				return
			}
			p = Pairing{ID: id, Code: code, Nick: inv.Nick, Name: q.Name, SessionJKT: q.SessionJKT, ConfirmJKT: q.ConfirmJKT,
				SecretHash: hashToken(secret), Expires: expires}
			if err = s.Store.PutPairing(p); err == nil {
				created = true
				break
			}
		}
		if !created {
			fail(w, http.StatusServiceUnavailable, "не удалось сохранить pairing")
			return
		}
		if _, ok := s.validPair(id, secret, inv.Nick); !ok {
			fail(w, http.StatusServiceUnavailable, "не удалось сохранить pairing")
			return
		}
		s.Log.Printf("event=pair.created nick=%s pairing=%s device=%s expires=%s", inv.Nick, hashToken(id), pairDeviceID(p.ConfirmJKT), expires.UTC().Format(time.RFC3339))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{"pair": pairPublic(p), "secret": secret})
	})

	m.HandleFunc("/v1/pair/lookup", s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, ok := readSmall(w, r)
		if !ok {
			return
		}
		var q struct{ Code string }
		if json.Unmarshal(body, &q) != nil {
			fail(w, http.StatusBadRequest, "json")
			return
		}
		p, err := s.Store.PairingByCode(normalizePairCode(q.Code))
		if err != nil || !s.now().Before(p.Expires) {
			fail(w, http.StatusNotFound, "код не найден или истёк")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(pairPublic(p))
	}))

	m.HandleFunc("/v1/pair/approve", s.api(http.MethodPost, func(w http.ResponseWriter, r *http.Request, id *Identity) {
		body, ok := readSmall(w, r)
		if !ok {
			return
		}
		status, resp, ok := s.kgJSON(w, r, "/v1/actions/verify", body)
		if !ok {
			return
		}
		if status != http.StatusOK {
			relay(w, status, resp)
			return
		}
		var v struct {
			Action struct {
				Type       string `json:"type"`
				Pairing    string `json:"pairing"`
				User       string `json:"user"`
				Target     string `json:"target"`
				Name       string `json:"name"`
				Code       string `json:"code"`
				SessionJKT string `json:"session_jkt"`
			} `json:"action"`
			User     string `json:"user"`
			DeviceID string `json:"device_id"`
		}
		if json.Unmarshal(resp, &v) != nil || v.Action.Type != "pair_approve" || v.User != id.User || v.DeviceID != id.DeviceID {
			fail(w, http.StatusForbidden, "действие подписано не этим устройством")
			return
		}
		p, err := s.Store.Pairing(v.Action.Pairing)
		if err != nil || !s.now().Before(p.Expires) || v.Action.User != p.Nick || v.Action.Name != p.Name ||
			v.Action.Code != p.Code || v.Action.SessionJKT != p.SessionJKT || v.Action.Target != pairDeviceID(p.ConfirmJKT) {
			fail(w, http.StatusForbidden, "подпись относится к другому pairing")
			return
		}
		p, err = s.Store.ApprovePairing(p.ID, id.User, s.now())
		if err != nil {
			fail(w, http.StatusConflict, "pairing уже подтверждён или истёк")
			return
		}
		s.Log.Printf("event=pair.approved nick=%s pairing=%s by=%s device=%s", p.Nick, hashToken(p.ID), id.User, pairDeviceID(p.ConfirmJKT))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(pairPublic(p))
	}))
}
