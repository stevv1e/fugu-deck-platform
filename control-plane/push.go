package controlplane

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Push-уведомления (Firebase Cloud Messaging, HTTP v1). Ключ сервисного аккаунта Firebase есть только у
// control-plane: пространства складывают события в свою очередь (/internal/outbox), control-plane забирает их и
// рассылает. В уведомлении — тип события и куда вести по нажатию; текста переписки в нём нет: оно проходит через Google.

// PushSender — отправка одного уведомления на одно устройство. ErrPushGone — токен больше не действует.
type PushSender interface {
	Send(ctx context.Context, token string, n Notification) error
}

var ErrPushGone = errors.New("токен устройства больше не действует")

// Notification — что увидит человек и что получит приложение по нажатию.
type Notification struct {
	Title, Body string
	Data        map[string]string
}

// FCM — отправитель через FCM HTTP v1 с OAuth-токеном сервисного аккаунта (JWT RS256, обмен на access token).
type FCM struct {
	ProjectID   string
	ClientEmail string
	TokenURI    string
	Key         *rsa.PrivateKey
	HTTP        *http.Client
	Endpoint    string // https://fcm.googleapis.com (в тестах подменяется)

	mu      sync.Mutex
	token   string
	expires time.Time
}

// LoadFCM читает JSON ключа сервисного аккаунта Firebase.
func LoadFCM(path string, hc *http.Client) (*FCM, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sa struct {
		Type        string `json:"type"`
		ProjectID   string `json:"project_id"`
		PrivateKey  string `json:"private_key"`
		ClientEmail string `json:"client_email"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(raw, &sa); err != nil || sa.Type != "service_account" || sa.ProjectID == "" || sa.ClientEmail == "" {
		return nil, errors.New("это не ключ сервисного аккаунта Firebase")
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("ключ сервисного аккаунта: нет закрытого ключа")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("ключ сервисного аккаунта: ожидается RSA")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}
	return &FCM{ProjectID: sa.ProjectID, ClientEmail: sa.ClientEmail, TokenURI: sa.TokenURI, Key: rk, HTTP: hc,
		Endpoint: "https://fcm.googleapis.com"}, nil
}

func (f *FCM) accessToken(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.token != "" && time.Now().Before(f.expires) {
		return f.token, nil
	}
	now := time.Now()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	cl, _ := json.Marshal(map[string]any{"iss": f.ClientEmail, "scope": "https://www.googleapis.com/auth/firebase.messaging",
		"aud": f.TokenURI, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	in := enc.EncodeToString(hdr) + "." + enc.EncodeToString(cl)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {in + "." + enc.EncodeToString(sig)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := f.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&out) != nil || out.AccessToken == "" {
		return "", fmt.Errorf("Google OAuth: HTTP %d", r.StatusCode)
	}
	f.token, f.expires = out.AccessToken, now.Add(time.Duration(out.ExpiresIn)*time.Second-5*time.Minute)
	return f.token, nil
}

func (f *FCM) Send(ctx context.Context, token string, n Notification) error {
	at, err := f.accessToken(ctx)
	if err != nil {
		return err
	}
	msg := map[string]any{"message": map[string]any{
		"token":        token,
		"notification": map[string]string{"title": n.Title, "body": n.Body},
		"data":         n.Data,
		// high — чтобы Android доставил сразу, а не отложил до выхода из режима сна
		"android": map[string]any{"priority": "high", "notification": map[string]string{"channel_id": "agent"}},
	}}
	body, _ := json.Marshal(msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.Endpoint+"/v1/projects/"+f.ProjectID+"/messages:send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+at)
	req.Header.Set("Content-Type", "application/json")
	r, err := f.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	switch {
	case r.StatusCode == http.StatusOK:
		return nil
	case r.StatusCode == http.StatusNotFound || strings.Contains(string(out), "UNREGISTERED") ||
		(r.StatusCode == http.StatusBadRequest && strings.Contains(string(out), "registration token")):
		return ErrPushGone // приложение удалено или токен сменился
	case r.StatusCode == http.StatusUnauthorized:
		f.mu.Lock()
		f.token = ""
		f.mu.Unlock()
	}
	return fmt.Errorf("FCM: HTTP %d: %.200s", r.StatusCode, out)
}

// ---------------- приём токенов и рассылка ----------------

// Токен FCM: буквы, цифры и «:-_», до 4 КБ (официальной длины нет, обычно ~160 символов).
var pushTokenRe = regexp.MustCompile(`^[A-Za-z0-9:_-]{20,}$`)

func (s *Server) registerPush(m *http.ServeMux) {
	// Устройство сообщает свой токен FCM (после входа и при его смене). Токен привязан к опознанному устройству.
	m.HandleFunc("/v1/push/token", s.apiAny(func(w http.ResponseWriter, r *http.Request, id *Identity) {
		switch r.Method {
		case http.MethodPost:
			body, ok := readSmall(w, r)
			if !ok {
				return
			}
			var q struct {
				Token string `json:"token"`
			}
			if json.Unmarshal(body, &q) != nil || len(q.Token) > 4096 || !pushTokenRe.MatchString(q.Token) {
				fail(w, http.StatusBadRequest, "нужен токен FCM")
				return
			}
			if err := s.Store.PutPushToken(id.User, id.DeviceID, q.Token); err != nil {
				fail(w, http.StatusServiceUnavailable, "временно недоступно")
				return
			}
			s.Log.Printf("event=push.token user=%s device=%s", id.User, id.DeviceID)
		case http.MethodDelete: // уведомления выключены на телефоне
			if err := s.Store.DeletePushToken(id.DeviceID); err != nil {
				fail(w, http.StatusServiceUnavailable, "временно недоступно")
				return
			}
		default:
			fail(w, http.StatusMethodNotAllowed, "POST или DELETE")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "enabled": s.Push != nil})
	}))
}

// notify рассылает уведомление всем устройствам пользователя; недействительные токены забываются.
func (s *Server) notify(ctx context.Context, nick string, n Notification) {
	if s.Push == nil {
		return
	}
	toks, err := s.Store.PushTokens(nick)
	if err != nil {
		return
	}
	if n.Data == nil {
		n.Data = map[string]string{}
	}
	n.Data["api"] = s.Cfg.APIURL // приложение по нему находит кластер
	for _, t := range toks {
		err := s.Push.Send(ctx, t.Token, n)
		switch {
		case errors.Is(err, ErrPushGone):
			s.Store.DeletePushToken(t.Device)
			s.Log.Printf("event=push.token_gone user=%s device=%s", nick, t.Device)
		case err != nil:
			s.Log.Printf("event=push.failed user=%s device=%s err=%q", nick, t.Device, err.Error())
		default:
			s.Log.Printf("event=push.sent user=%s device=%s kind=%s", nick, t.Device, n.Data["kind"])
		}
	}
}

// outboxEvent — событие из очереди пространства (backend app/outbox.py).
type outboxEvent struct {
	Seq          int    `json:"seq"`
	User         string `json:"user"`
	Kind         string `json:"kind"`
	Conversation string `json:"conversation_id"`
	Project      string `json:"project_id"`
	Tool         string `json:"tool"`
	Percent      int    `json:"percent"`
}

// notificationFor — текст уведомления по событию. Только тип и название инструмента — без переписки.
func notificationFor(space string, e outboxEvent) (Notification, bool) {
	d := map[string]string{"kind": e.Kind, "space": space, "cid": e.Conversation, "pid": e.Project}
	switch e.Kind {
	case "approval":
		body := "Откройте чат, чтобы разрешить или отклонить"
		if e.Tool != "" {
			body = e.Tool + " — откройте чат, чтобы разрешить или отклонить"
		}
		return Notification{Title: "Агент ждёт подтверждения", Body: body, Data: d}, true
	case "done":
		return Notification{Title: "Агент ответил", Body: "Задание выполнено — ответ в чате", Data: d}, true
	case "error":
		return Notification{Title: "Агент остановился", Body: "Задание прервалось с ошибкой — подробности в чате", Data: d}, true
	case "sponsor":
		if e.Percent >= 100 {
			return Notification{Title: "Лимит на модель исчерпан", Body: "Вы оплачиваете модель в общем чате: агент там остановится. Продлите или отзовите разрешение", Data: d}, true
		}
		return Notification{Title: fmt.Sprintf("Расход на модель: %d %%", e.Percent), Body: "Вы оплачиваете модель в общем чате", Data: d}, true
	}
	return Notification{}, false
}

type outboxCursor struct {
	boot string
	last int
}

// PollOutboxes — один проход: забрать новые события у работающих пространств и разослать уведомления.
func (s *Server) PollOutboxes(ctx context.Context) {
	if s.Push == nil || s.Spaces == nil {
		return
	}
	spaces, err := s.Spaces.List(ctx)
	if err != nil {
		return
	}
	for _, sp := range spaces {
		if sp.Suspended || sp.Phase != "Ready" || sp.Namespace == "" {
			continue
		}
		s.pollOutbox(ctx, sp)
	}
}

func (s *Server) pollOutbox(ctx context.Context, sp SpaceInfo) {
	s.outbox.mu.Lock()
	if s.outbox.cur == nil {
		s.outbox.cur = map[string]outboxCursor{}
	}
	cur, known := s.outbox.cur[sp.Name]
	s.outbox.mu.Unlock()
	tok, err := s.signSpaceJWT(map[string]any{"aud": "space-internal:" + sp.Name, "sub": "control-plane",
		"action": "outbox", "boot": cur.boot, "after": cur.last})
	if err != nil {
		return
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.SpaceURL(sp.Namespace).String()+"/internal/outbox", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer r.Body.Close()
	var out struct {
		Boot   string        `json:"boot"`
		Events []outboxEvent `json:"events"`
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&out) != nil {
		return // агент старой версии (404) или перезапускается
	}
	last := cur.last
	if out.Boot != cur.boot {
		last = 0
	}
	for _, e := range out.Events {
		if e.Seq <= last {
			continue
		}
		last = e.Seq
		// Первое знакомство с очередью (control-plane перезапустился): накопленное за час не рассылаем — это уже
		// не новости, и человек не должен получить пачку старых уведомлений.
		if !known {
			continue
		}
		if !s.mayNotify(sp, e.User) {
			continue
		}
		if n, ok := notificationFor(sp.Name, e); ok {
			s.notify(ctx, e.User, n)
		}
	}
	s.outbox.mu.Lock()
	s.outbox.cur[sp.Name] = outboxCursor{boot: out.Boot, last: last}
	s.outbox.mu.Unlock()
}

// mayNotify — пространство не может попросить уведомить постороннего: адресат — владелец личного или участник общего.
func (s *Server) mayNotify(sp SpaceInfo, nick string) bool {
	if !strings.HasPrefix(sp.Name, "t-") {
		return nick == sp.Owner
	}
	ms, err := s.Store.Members(sp.Name)
	if err != nil {
		return false
	}
	for _, m := range ms {
		if m.Nick == nick {
			return true
		}
	}
	return false
}

// RunPush — опрос очередей пространств с заданным шагом, пока не отменён контекст.
func (s *Server) RunPush(ctx context.Context, every time.Duration) {
	if s.Push == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.Store.Leader("push") { // при нескольких репликах — одна (D73)
				s.PollOutboxes(ctx)
			}
		}
	}
}
