package keyguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

var ErrUnauthenticated = errors.New("вызывающий не опознан")

// Caller — кто пришёл: namespace и ServiceAccount из проверенного токена.
type Caller struct{ Namespace, ServiceAccount string }

type Authenticator interface {
	Authenticate(ctx context.Context, token string) (Caller, error)
}

// TokenReviewAuth — проверка проецируемого токена ServiceAccount через API Kubernetes (audience=keyguard).
// keyguard нужен ClusterRole system:auth-delegator. Результат кэшируется на 30 с по хешу токена.
type TokenReviewAuth struct {
	APIServer string
	Token     func() (string, error) // собственный токен keyguard для вызова TokenReview
	HTTP      *http.Client
	Audience  string

	mu    sync.Mutex
	cache map[[32]byte]cacheEntry
}

type cacheEntry struct {
	c   Caller
	exp time.Time
}

func (a *TokenReviewAuth) Authenticate(ctx context.Context, token string) (Caller, error) {
	if token == "" || len(token) > 8192 {
		return Caller{}, ErrUnauthenticated
	}
	h := sha256.Sum256([]byte(token))
	a.mu.Lock()
	if a.cache == nil {
		a.cache = map[[32]byte]cacheEntry{}
	}
	if e, ok := a.cache[h]; ok && time.Now().Before(e.exp) {
		a.mu.Unlock()
		return e.c, nil
	}
	a.mu.Unlock()

	own, err := a.Token()
	if err != nil {
		return Caller{}, err
	}
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
		"spec": map[string]any{"token": token, "audiences": []string{a.Audience}},
	})
	req, _ := http.NewRequestWithContext(ctx, "POST", a.APIServer+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+own)
	req.Header.Set("Content-Type", "application/json")
	r, err := a.HTTP.Do(req)
	if err != nil {
		return Caller{}, err
	}
	defer r.Body.Close()
	var tr struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			Audiences     []string `json:"audiences"`
			User          struct {
				Username string `json:"username"`
			} `json:"user"`
		} `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&tr); err != nil || r.StatusCode != 201 {
		return Caller{}, ErrUnauthenticated
	}
	st := tr.Status
	if !st.Authenticated || !contains(st.Audiences, a.Audience) {
		return Caller{}, ErrUnauthenticated
	}
	parts := strings.Split(st.User.Username, ":") // system:serviceaccount:<ns>:<sa>
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return Caller{}, ErrUnauthenticated // токен не ServiceAccount (например, пользователь) — не пускаем
	}
	c := Caller{Namespace: parts[2], ServiceAccount: parts[3]}
	a.mu.Lock()
	a.cache[h] = cacheEntry{c, time.Now().Add(30 * time.Second)}
	a.mu.Unlock()
	return c, nil
}

// StaticAuth — для тестов: токен → вызывающий.
type StaticAuth map[string]Caller

func (s StaticAuth) Authenticate(_ context.Context, t string) (Caller, error) {
	if c, ok := s[t]; ok {
		return c, nil
	}
	return Caller{}, ErrUnauthenticated
}
