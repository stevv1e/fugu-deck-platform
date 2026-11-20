package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// KeyguardHTTP — клиент keyguard. Токен читается из файла на каждый запрос: kubelet обновляет его сам.
type KeyguardHTTP struct {
	URL       string
	TokenPath string
	HTTP      *http.Client
}

func (k *KeyguardHTTP) Post(ctx context.Context, path string, body []byte) (int, []byte, error) {
	tok, err := os.ReadFile(k.TokenPath)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.URL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Content-Type", "application/json")
	r, err := k.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer r.Body.Close()
	resp, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	return r.StatusCode, resp, err
}

// KeycloakAdmin — Admin API Keycloak под сервисной учётной записью клиента (client credentials).
// Роль клиента — только управление пользователями realm deck; control-plane ею создаёт пользователя под приглашение.
type KeycloakAdmin struct {
	BaseURL      string // внутренний адрес: http://keycloak-service.deck-auth.svc.cluster.local:8080
	Realm        string
	ClientID     string
	ClientSecret string
	HTTP         *http.Client

	mu    sync.Mutex
	token string
	exp   time.Time
}

func (k *KeycloakAdmin) accessToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && time.Now().Before(k.exp) {
		return k.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {k.ClientID}, "client_secret": {k.ClientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		k.BaseURL+"/realms/"+k.Realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := k.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&t) != nil || t.AccessToken == "" {
		return "", fmt.Errorf("Keycloak не выдал токен сервисной учётной записи (HTTP %d)", r.StatusCode)
	}
	k.token, k.exp = t.AccessToken, time.Now().Add(time.Duration(t.ExpiresIn)*time.Second-15*time.Second)
	return k.token, nil
}

// EnsureUser создаёт пользователя без пароля с обязательным действием «зарегистрировать passkey».
// Уже существующий пользователь (409) — не ошибка: приглашение выпускают и для второго устройства.
func (k *KeycloakAdmin) EnsureUser(ctx context.Context, nick string) error {
	tok, err := k.accessToken(ctx)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"username": nick, "enabled": true, "requiredActions": []string{"webauthn-register-passwordless"},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.BaseURL+"/admin/realms/"+k.Realm+"/users", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	r, err := k.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	io.Copy(io.Discard, io.LimitReader(r.Body, 1<<16))
	switch r.StatusCode {
	case http.StatusCreated, http.StatusConflict:
		return nil
	case http.StatusUnauthorized:
		k.mu.Lock()
		k.token = ""
		k.mu.Unlock()
	}
	return errors.New("Keycloak не создал пользователя (HTTP " + http.StatusText(r.StatusCode) + ")")
}

// DeleteUser — удаление аккаунта: учётная запись и её passkey. Нет такой — не ошибка (повтор после обрыва).
func (k *KeycloakAdmin) DeleteUser(ctx context.Context, nick string) error {
	tok, err := k.accessToken(ctx)
	if err != nil {
		return err
	}
	call := func(method, path string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, k.BaseURL+"/admin/realms/"+k.Realm+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return k.HTTP.Do(req)
	}
	r, err := call(http.MethodGet, "/users?exact=true&username="+url.QueryEscape(nick))
	if err != nil {
		return err
	}
	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	err = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&users)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || err != nil {
		return errors.New("Keycloak: поиск пользователя (HTTP " + http.StatusText(r.StatusCode) + ")")
	}
	for _, u := range users {
		if u.Username != nick {
			continue
		}
		d, err := call(http.MethodDelete, "/users/"+url.PathEscape(u.ID))
		if err != nil {
			return err
		}
		d.Body.Close()
		if d.StatusCode != http.StatusNoContent && d.StatusCode != http.StatusNotFound {
			return errors.New("Keycloak не удалил пользователя (HTTP " + http.StatusText(d.StatusCode) + ")")
		}
	}
	return nil
}

// RemovePasskeys — удалить passkey пользователя (учётные данные WebAuthn). Нужно, когда потерян единственный
// телефон: иначе вход по новому приглашению просит passkey, оставшийся на потерянном. Пользователя нет — 0.
func (k *KeycloakAdmin) RemovePasskeys(ctx context.Context, nick string) (int, error) {
	tok, err := k.accessToken(ctx)
	if err != nil {
		return 0, err
	}
	call := func(method, path string, out any) (int, error) {
		req, err := http.NewRequestWithContext(ctx, method, k.BaseURL+"/admin/realms/"+k.Realm+path, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		r, err := k.HTTP.Do(req)
		if err != nil {
			return 0, err
		}
		defer r.Body.Close()
		if out != nil && r.StatusCode == http.StatusOK {
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(out); err != nil {
				return 0, err
			}
		}
		return r.StatusCode, nil
	}
	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if st, err := call(http.MethodGet, "/users?exact=true&username="+url.QueryEscape(nick), &users); err != nil || st != http.StatusOK {
		return 0, fmt.Errorf("Keycloak: поиск пользователя (HTTP %d): %v", st, err)
	}
	n := 0
	for _, u := range users {
		if u.Username != nick {
			continue
		}
		var creds []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		if st, err := call(http.MethodGet, "/users/"+url.PathEscape(u.ID)+"/credentials", &creds); err != nil || st != http.StatusOK {
			return n, fmt.Errorf("Keycloak: учётные данные (HTTP %d): %v", st, err)
		}
		for _, c := range creds {
			if c.Type != "webauthn" && c.Type != "webauthn-passwordless" {
				continue
			}
			st, err := call(http.MethodDelete, "/users/"+url.PathEscape(u.ID)+"/credentials/"+url.PathEscape(c.ID), nil)
			if err != nil || (st != http.StatusNoContent && st != http.StatusNotFound) {
				return n, fmt.Errorf("Keycloak не удалил passkey (HTTP %d): %v", st, err)
			}
			n++
		}
	}
	return n, nil
}
