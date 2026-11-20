package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type testPair struct {
	ID         string `json:"id"`
	Code       string `json:"code"`
	User       string `json:"user"`
	Name       string `json:"name"`
	DeviceID   string `json:"device_id"`
	SessionJKT string `json:"session_jkt"`
	Expires    string `json:"expires"`
	Approved   bool   `json:"approved"`
}

func startTestPair(t *testing.T, a *authStand) (testPair, string, string) {
	t.Helper()
	tok := a.invite(t, "anna")
	sess, conf := strings.Repeat("s", 43), strings.Repeat("c", 43)
	w := do(a.s.PublicHandler(), "POST", "/v1/pair/start", map[string]string{"X-Deck-Invite": tok},
		fmt.Sprintf(`{"name":"My PC","session_jkt":%q,"confirm_jkt":%q}`, sess, conf))
	if w.Code != 200 {
		t.Fatalf("pair/start: %d %s", w.Code, w.Body)
	}
	var out struct {
		Pair   testPair `json:"pair"`
		Secret string   `json:"secret"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Pair.User != "anna" || out.Pair.DeviceID != "d-"+conf[:16] || out.Secret == "" {
		t.Fatalf("pair/start ответ: %s", w.Body)
	}
	return out.Pair, out.Secret, tok
}

func pairCookies(t *testing.T, a *authStand, p testPair, secret, tok string) string {
	t.Helper()
	q := url.Values{"invite": {tok}, "next": {"https://id.deck.test/realms/deck/x"}, "pair": {p.ID}, "pair_secret": {secret}}
	w := do(a.s.PublicHandler(), "GET", "/start?"+q.Encode(), nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("/start pair: %d %s", w.Code, w.Body)
	}
	var invite, pair string
	for _, c := range w.Result().Cookies() {
		if c.Name == inviteCookie {
			invite = c.Value
		}
		if c.Name == pairCookie {
			pair = c.Value
		}
	}
	if invite == "" || pair == "" {
		t.Fatalf("нет pairing cookie: %v", w.Result().Cookies())
	}
	return inviteCookie + "=" + invite + "; " + pairCookie + "=" + pair
}

func TestDesktopPairLifecycle(t *testing.T) {
	a := newAuthStand(t)
	p, secret, tok := startTestPair(t, a)
	cookie := pairCookies(t, a, p, secret, tok)
	auth := a.s.AuthHandler()
	w := do(auth, "GET", "/auth/invite", map[string]string{"Cookie": cookie}, "")
	if w.Code != 200 || w.Header().Get(nickHeader) != "anna" || w.Header().Get(pairStatusHeader) != "pending" {
		t.Fatalf("pending gate: %d %v", w.Code, w.Header())
	}
	w = a.req("POST", "/v1/pair/lookup", `{"code":"`+p.Code+`"}`, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"device_id":"`+p.DeviceID+`"`) {
		t.Fatalf("lookup: %d %s", w.Code, w.Body)
	}
	a.kg.resp = fmt.Sprintf(`{"action":{"type":"pair_approve","pairing":%q,"user":"anna","target":%q,"name":"My PC","code":%q,"session_jkt":%q},"user":"anna","device_id":"d-device1"}`,
		p.ID, p.DeviceID, p.Code, p.SessionJKT)
	w = a.req("POST", "/v1/pair/approve", `{"jws":"x.y.z"}`, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"approved":true`) {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	w = do(auth, "GET", "/auth/invite", map[string]string{"Cookie": cookie}, "")
	if w.Code != 200 || w.Header().Get(pairStatusHeader) != "approved" {
		t.Fatalf("approved gate: %d %v", w.Code, w.Header())
	}
	if w = a.req("POST", "/v1/pair/approve", `{"jws":"x.y.z"}`, nil); w.Code != http.StatusConflict {
		t.Fatalf("повторное подтверждение: %d %s", w.Code, w.Body)
	}
}

func TestDesktopPairRejectsSubstitution(t *testing.T) {
	a := newAuthStand(t)
	p, secret, tok := startTestPair(t, a)
	if w := do(a.s.PublicHandler(), "POST", "/v1/pair/start", nil, `{}`); w.Code != 401 {
		t.Fatalf("start без приглашения: %d", w.Code)
	}
	q := url.Values{"invite": {tok}, "next": {"https://id.deck.test/realms/deck/x"}, "pair": {p.ID}, "pair_secret": {strings.Repeat("x", 43)}}
	if w := do(a.s.PublicHandler(), "GET", "/start?"+q.Encode(), nil, ""); w.Code != 403 {
		t.Fatalf("чужой pairing secret: %d", w.Code)
	}
	if w := a.req("POST", "/v1/pair/lookup", `{"code":"NOTFOUND"}`, nil); w.Code != 404 {
		t.Fatalf("неизвестный код: %d", w.Code)
	}
	valid := map[string]any{"type": "pair_approve", "pairing": p.ID, "user": "anna", "target": p.DeviceID, "name": "My PC", "code": p.Code, "session_jkt": p.SessionJKT}
	for name, change := range map[string]func(){
		"другой пользователь": func() { valid["user"] = "bob" },
		"другое устройство":   func() { valid["target"] = "d-dddddddddddddddd" },
		"другой ключ сессии":  func() { valid["session_jkt"] = strings.Repeat("x", 43) },
		"другой код":          func() { valid["code"] = "ABCDEFGH" },
		"подписал другой":     func() { valid["user"] = "anna" },
	} {
		change()
		raw, _ := json.Marshal(map[string]any{"action": valid, "user": "anna", "device_id": "d-device1"})
		if name == "подписал другой" {
			raw, _ = json.Marshal(map[string]any{"action": valid, "user": "bob", "device_id": "d-device1"})
		}
		a.kg.resp = string(raw)
		if w := a.req("POST", "/v1/pair/approve", `{"jws":"x.y.z"}`, nil); w.Code == 200 {
			t.Errorf("%s: pairing подтверждён", name)
		}
		if name != "подписал другой" {
			switch name {
			case "другой пользователь":
				valid["user"] = "anna"
			case "другое устройство":
				valid["target"] = p.DeviceID
			case "другой ключ сессии":
				valid["session_jkt"] = p.SessionJKT
			case "другой код":
				valid["code"] = p.Code
			}
		}
	}
	stored, err := a.s.Store.Pairing(p.ID)
	if err != nil || stored.Approved {
		t.Fatalf("после атак pairing подтверждён: %+v %v", stored, err)
	}
	_ = secret
}
