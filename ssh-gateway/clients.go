package sshgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Caller — кто обратился к шлюзу: namespace и ServiceAccount из проецируемого токена (audience=ssh-gateway).
type Caller struct{ Namespace, ServiceAccount string }

var ErrUnauthenticated = errors.New("не опознан")

// Auth опознаёт вызывающего по токену.
type Auth interface {
	Authenticate(ctx context.Context, token string) (Caller, error)
}

// StaticAuth — для тестов и стендов: токен → вызывающий.
type StaticAuth map[string]Caller

func (s StaticAuth) Authenticate(_ context.Context, token string) (Caller, error) {
	c, ok := s[token]
	if !ok {
		return Caller{}, ErrUnauthenticated
	}
	return c, nil
}

// TokenReviewAuth — проверка токена через API Kubernetes (TokenReview) с требованием своей audience: токен,
// выпущенный для keyguard или API-сервера, здесь не годится.
type TokenReviewAuth struct {
	APIServer string
	Token     func() (string, error) // собственный токен шлюза для вызова TokenReview
	HTTP      *http.Client
	Audience  string

	mu    sync.Mutex
	cache map[[32]byte]cached
}

type cached struct {
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
		a.cache = map[[32]byte]cached{}
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
	body, _ := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
		"spec": map[string]any{"token": token, "audiences": []string{a.Audience}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.APIServer+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return Caller{}, err
	}
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
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&tr); err != nil || r.StatusCode/100 != 2 {
		return Caller{}, fmt.Errorf("TokenReview: HTTP %d", r.StatusCode)
	}
	okAud := false
	for _, x := range tr.Status.Audiences {
		okAud = okAud || x == a.Audience
	}
	// system:serviceaccount:<namespace>:<имя>
	p := strings.Split(tr.Status.User.Username, ":")
	if !tr.Status.Authenticated || !okAud || len(p) != 4 || p[0] != "system" || p[1] != "serviceaccount" {
		return Caller{}, ErrUnauthenticated
	}
	c := Caller{Namespace: p[2], ServiceAccount: p[3]}
	a.mu.Lock()
	if len(a.cache) > 2000 {
		a.cache = map[[32]byte]cached{}
	}
	a.cache[h] = cached{c, time.Now().Add(30 * time.Second)}
	a.mu.Unlock()
	return c, nil
}

// Verified — ответ keyguard на /v1/actions/verify: разобранное действие и кто его подписал.
type Verified struct {
	Action   map[string]any `json:"action"`
	User     string         `json:"user"`
	DeviceID string         `json:"device_id"`
}

// ErrRejected — keyguard подпись не принял (повторять бессмысленно; «keyguard недоступен» — другая ошибка).
var ErrRejected = errors.New("подпись не принята")

// Verifier проверяет подписанное действие. Каждую подпись можно проверить один раз: keyguard запоминает её номер.
type Verifier interface {
	Verify(ctx context.Context, jws string) (Verified, error)
}

// KeyguardHTTP — keyguard по HTTP с токеном ServiceAccount шлюза (audience=keyguard).
type KeyguardHTTP struct {
	URL       string
	TokenPath string
	HTTP      *http.Client
}

func (k *KeyguardHTTP) Verify(ctx context.Context, jws string) (Verified, error) {
	var v Verified
	tok, err := os.ReadFile(k.TokenPath)
	if err != nil {
		return v, err
	}
	body, _ := json.Marshal(map[string]string{"jws": jws})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.URL+"/v1/actions/verify", bytes.NewReader(body))
	if err != nil {
		return v, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Content-Type", "application/json")
	r, err := k.HTTP.Do(req)
	if err != nil {
		return v, err
	}
	defer r.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	switch {
	case r.StatusCode == http.StatusOK:
		return v, json.Unmarshal(out, &v)
	case r.StatusCode == http.StatusBadRequest || r.StatusCode == http.StatusForbidden:
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(out, &e)
		return v, fmt.Errorf("%w: %s", ErrRejected, e.Error)
	}
	return v, fmt.Errorf("keyguard: HTTP %d", r.StatusCode)
}

// CertSigner выпускает SSH-сертификат на публичный ключ: principal, срок, без проброса чего-либо.
type CertSigner interface {
	// Sign возвращает сертификат в формате authorized_keys ("ssh-ed25519-cert-v01@openssh.com AAAA…").
	Sign(ctx context.Context, publicKey, principal string) (string, error)
	// CAPublicKey — публичный ключ CA: его владелец сервера кладёт в TrustedUserCAKeys.
	CAPublicKey(ctx context.Context) (string, error)
}

// BaoSigner — SSH CA в OpenBao (mount ssh-client-signer, роль agent). Вход — проецируемым токеном ServiceAccount.
type BaoSigner struct {
	Addr     string
	Role     string // роль входа Kubernetes: ssh-gateway
	JWTPath  string
	TTL      time.Duration
	SourceIP string // исходящий адрес кластера: сертификат действует только с него (пусто — без ограничения)
	HTTP     *http.Client
	// StaticToken — готовый токен OpenBao вместо входа через Kubernetes (стенды и проверка на настоящем OpenBao).
	StaticToken string

	mu  sync.Mutex
	tok string
	exp time.Time
	ca  string
}

func (b *BaoSigner) token(ctx context.Context) (string, error) {
	if b.StaticToken != "" {
		return b.StaticToken, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tok != "" && time.Now().Before(b.exp) {
		return b.tok, nil
	}
	jwt, err := os.ReadFile(b.JWTPath)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{"role": b.Role, "jwt": strings.TrimSpace(string(jwt))})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.Addr+"/v1/auth/kubernetes/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	r, err := b.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&out) != nil || out.Auth.ClientToken == "" {
		return "", fmt.Errorf("вход в OpenBao: HTTP %d", r.StatusCode)
	}
	b.tok, b.exp = out.Auth.ClientToken, time.Now().Add(time.Duration(out.Auth.LeaseDuration)*time.Second*8/10)
	return b.tok, nil
}

func (b *BaoSigner) call(ctx context.Context, method, path string, body any, out any) error {
	tok, err := b.token(ctx)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.Addr+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", tok)
	r, err := b.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if r.StatusCode/100 != 2 {
		if r.StatusCode == http.StatusForbidden {
			b.mu.Lock()
			b.tok = "" // токен мог быть отозван: войдём заново при следующем вызове
			b.mu.Unlock()
		}
		return fmt.Errorf("OpenBao %s: HTTP %d", path, r.StatusCode)
	}
	return json.Unmarshal(raw, out)
}

func (b *BaoSigner) Sign(ctx context.Context, publicKey, principal string) (string, error) {
	req := map[string]any{"public_key": publicKey, "valid_principals": principal, "cert_type": "user",
		"ttl": fmt.Sprintf("%ds", int(b.TTL.Seconds())), "extensions": map[string]string{"permit-pty": ""}}
	if b.SourceIP != "" {
		req["critical_options"] = map[string]string{"source-address": b.SourceIP}
	}
	var out struct {
		Data struct {
			SignedKey string `json:"signed_key"`
		} `json:"data"`
	}
	if err := b.call(ctx, http.MethodPost, "/v1/ssh-client-signer/sign/agent", req, &out); err != nil {
		return "", err
	}
	if out.Data.SignedKey == "" {
		return "", errors.New("OpenBao не вернул сертификат")
	}
	return strings.TrimSpace(out.Data.SignedKey), nil
}

func (b *BaoSigner) CAPublicKey(ctx context.Context) (string, error) {
	b.mu.Lock()
	ca := b.ca
	b.mu.Unlock()
	if ca != "" {
		return ca, nil
	}
	var out struct {
		Data struct {
			PublicKey string `json:"public_key"`
		} `json:"data"`
	}
	if err := b.call(ctx, http.MethodGet, "/v1/ssh-client-signer/config/ca", nil, &out); err != nil {
		return "", err
	}
	ca = strings.TrimSpace(out.Data.PublicKey)
	if ca == "" {
		return "", errors.New("OpenBao не вернул ключ CA")
	}
	b.mu.Lock()
	b.ca = ca
	b.mu.Unlock()
	return ca, nil
}
