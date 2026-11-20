package controlplane

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Отправка через FCM HTTP v1: OAuth-токен по подписанному JWT, сообщение без текста переписки, мёртвый токен.
func TestFCMSend(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	var mu sync.Mutex
	var got map[string]any
	var oauthCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/token":
			oauthCalls++
			r.ParseForm()
			parts := strings.Split(r.Form.Get("assertion"), ".")
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			cl, _ := base64.RawURLEncoding.DecodeString(parts[1])
			if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig) != nil || !strings.Contains(string(cl), "firebase.messaging") {
				http.Error(w, "bad jwt", 400)
				return
			}
			io.WriteString(w, `{"access_token":"at-1","expires_in":3600}`)
		case "/v1/projects/fugu-test/messages:send":
			if r.Header.Get("Authorization") != "Bearer at-1" {
				http.Error(w, "unauth", 401)
				return
			}
			json.NewDecoder(r.Body).Decode(&got)
			if strings.Contains(string(must(json.Marshal(got))), "dead") {
				w.WriteHeader(404)
				io.WriteString(w, `{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}`)
				return
			}
			io.WriteString(w, `{"name":"projects/fugu-test/messages/1"}`)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "fugu-test", "client_email": "x@fugu-test.iam",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "token_uri": srv.URL + "/token"})
	p := filepath.Join(dir, "sa.json")
	os.WriteFile(p, sa, 0600)
	f, err := LoadFCM(p, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.Endpoint = srv.URL
	n := Notification{Title: "Агент ждёт подтверждения", Body: "…", Data: map[string]string{"kind": "approval", "cid": "c1"}}
	if err := f.Send(context.Background(), "tok-live-0123456789abcdef", n); err != nil {
		t.Fatal(err)
	}
	m := got["message"].(map[string]any)
	if m["token"] != "tok-live-0123456789abcdef" || m["data"].(map[string]any)["cid"] != "c1" || m["android"].(map[string]any)["priority"] != "high" {
		t.Fatalf("сообщение: %v", got)
	}
	if err := f.Send(context.Background(), "dead-token-0123456789", n); err != ErrPushGone {
		t.Fatalf("мёртвый токен: %v", err)
	}
	if oauthCalls != 1 {
		t.Fatalf("OAuth-токен должен переиспользоваться: %d", oauthCalls)
	}
	os.WriteFile(p, []byte(`{"type":"authorized_user"}`), 0600)
	if _, err := LoadFCM(p, nil); err == nil {
		t.Fatal("принят не ключ сервисного аккаунта")
	}
}

func must(b []byte, _ error) []byte { return b }

type fakePush struct {
	mu   sync.Mutex
	sent []string // токен|kind|cid
	gone map[string]bool
}

func (f *fakePush) Send(_ context.Context, token string, n Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gone[token] {
		return ErrPushGone
	}
	f.sent = append(f.sent, token+"|"+n.Data["kind"]+"|"+n.Data["cid"])
	return nil
}

func TestPushTokensAndOutbox(t *testing.T) {
	st := newSpaceStand(t)
	push := &fakePush{gone: map[string]bool{}}
	st.s.Push = push
	body := func(tok string) string { b, _ := json.Marshal(map[string]string{"token": tok}); return string(b) }
	if w := st.req("POST", "/v1/push/token", body("короткий"), nil); w.Code != 400 {
		t.Fatalf("негодный токен: %d", w.Code)
	}
	if w := st.req("POST", "/v1/push/token", body("fcm-token-anna-0123456789"), nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":true`) {
		t.Fatalf("регистрация токена: %d %s", w.Code, w.Body)
	}

	// «Агент» с очередью уведомлений.
	var mu sync.Mutex
	boot, events := "b1", []map[string]any{}
	var lastClaims map[string]any
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct{ Token string }
		json.NewDecoder(r.Body).Decode(&q)
		parts := strings.Split(q.Token, ".")
		cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
		mu.Lock()
		defer mu.Unlock()
		json.Unmarshal(cb, &lastClaims)
		after := 0
		if lastClaims["boot"] == boot {
			after = int(lastClaims["after"].(float64))
		}
		var out []map[string]any
		for _, e := range events {
			if e["seq"].(int) > after {
				out = append(out, e)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"boot": boot, "events": out})
	}))
	defer agent.Close()
	u, _ := url.Parse(agent.URL)
	st.s.SpaceURL = func(string) *url.URL { return u }
	st.req("POST", "/v1/space", "", nil)
	s := st.sp.m["anna"]
	s.Phase, s.Namespace = "Ready", "deck-u-anna"
	st.sp.m["anna"] = s
	add := func(user, kind, cid string) {
		mu.Lock()
		events = append(events, map[string]any{"seq": len(events) + 1, "user": user, "kind": kind, "conversation_id": cid})
		mu.Unlock()
	}
	add("anna", "done", "old")
	ctx := context.Background()
	st.s.PollOutboxes(ctx)
	if len(push.sent) != 0 || lastClaims["aud"] != "space-internal:anna" || lastClaims["action"] != "outbox" {
		t.Fatalf("первый проход не должен рассылать накопленное: %v %v", push.sent, lastClaims)
	}
	add("anna", "approval", "c1")
	add("bob", "done", "c2") // пространство Анны не может уведомить Боба
	st.s.PollOutboxes(ctx)
	if strings.Join(push.sent, ",") != "fcm-token-anna-0123456789|approval|c1" {
		t.Fatalf("рассылка: %v", push.sent)
	}
	st.s.PollOutboxes(ctx)
	if len(push.sent) != 1 {
		t.Fatalf("повтор того же события: %v", push.sent)
	}
	// Агент перезапустился: новая очередь читается с начала.
	mu.Lock()
	boot, events = "b2", nil
	mu.Unlock()
	add("anna", "error", "c3")
	st.s.PollOutboxes(ctx)
	if len(push.sent) != 2 || !strings.HasSuffix(push.sent[1], "|error|c3") {
		t.Fatalf("после перезапуска агента: %v", push.sent)
	}
	// Удалённое приложение: токен забывается.
	push.gone["fcm-token-anna-0123456789"] = true
	add("anna", "done", "c4")
	st.s.PollOutboxes(ctx)
	if toks, _ := st.s.Store.PushTokens("anna"); len(toks) != 0 {
		t.Fatalf("мёртвый токен не забыт: %v", toks)
	}
	// Спящее пространство не опрашивается.
	s.Suspended = true
	st.sp.m["anna"] = s
	lastClaims = nil
	st.s.PollOutboxes(ctx)
	if lastClaims != nil {
		t.Fatal("опрошено спящее пространство")
	}
}

func TestNotificationTexts(t *testing.T) {
	for _, e := range []outboxEvent{{Kind: "approval", Tool: "Запись файлов"}, {Kind: "done"}, {Kind: "error"}, {Kind: "sponsor", Percent: 80}, {Kind: "sponsor", Percent: 100}} {
		n, ok := notificationFor("t-abc123", e)
		if !ok || n.Title == "" || n.Data["space"] != "t-abc123" {
			t.Errorf("%+v: %+v", e, n)
		}
	}
	if n, _ := notificationFor("x", outboxEvent{Kind: "sponsor", Percent: 80}); !strings.Contains(n.Title, "80 %") {
		t.Errorf("процент: %q", n.Title)
	}
	if _, ok := notificationFor("x", outboxEvent{Kind: "неизвестно"}); ok {
		t.Error("неизвестное событие не должно уведомлять")
	}
}
