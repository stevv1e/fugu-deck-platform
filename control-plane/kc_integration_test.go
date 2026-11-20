package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Тест на настоящем Keycloak: scripts/keycloak_test.sh поднимает контейнер и задаёт CP_KC_URL и CP_KC_SECRET.
func TestKeycloakEnsureUser(t *testing.T) {
	base, secret := os.Getenv("CP_KC_URL"), os.Getenv("CP_KC_SECRET")
	if base == "" {
		t.Skip("нужен CP_KC_URL (scripts/keycloak_test.sh)")
	}
	hc := &http.Client{Timeout: 20 * time.Second}
	ctx := context.Background()
	k := &KeycloakAdmin{BaseURL: base, Realm: "deck", ClientID: "deck-control-plane", ClientSecret: secret, HTTP: hc}

	if err := k.EnsureUser(ctx, "newbie"); err != nil {
		t.Fatal(err)
	}
	if err := k.EnsureUser(ctx, "newbie"); err != nil {
		t.Fatalf("повторное приглашение того же пользователя: %v", err)
	}

	// Смотрим глазами администратора master: пользователь один, без пароля, с обязательной регистрацией passkey.
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {"admin-pass"}}
	r, err := hc.Post(base+"/realms/master/protocol/openid-connect/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(r.Body).Decode(&tok)
	r.Body.Close()
	get := func(path string, out any) {
		t.Helper()
		req, _ := http.NewRequest("GET", base+"/admin/realms/deck"+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		r, err := hc.Do(req)
		if err != nil || r.StatusCode != 200 {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer r.Body.Close()
		json.NewDecoder(r.Body).Decode(out)
	}
	var users []struct {
		ID              string   `json:"id"`
		Enabled         bool     `json:"enabled"`
		RequiredActions []string `json:"requiredActions"`
	}
	get("/users?exact=true&username=newbie", &users)
	if len(users) != 1 || !users[0].Enabled || len(users[0].RequiredActions) != 1 || users[0].RequiredActions[0] != "webauthn-register-passwordless" {
		t.Fatalf("пользователь: %+v", users)
	}
	var creds []map[string]any
	get("/users/"+users[0].ID+"/credentials", &creds)
	if len(creds) != 0 {
		t.Fatalf("у нового пользователя есть учётные данные: %v", creds)
	}

	// Права сервисной учётной записи: пользователей создаёт, а realm и клиентов менять не может.
	at, err := k.accessToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "", `{"registrationAllowed":true}`},
		{"POST", "/clients", `{"clientId":"evil","publicClient":true}`},
		{"GET", "/clients", ""},
	} {
		req, _ := http.NewRequest(c.method, base+"/admin/realms/deck"+c.path, strings.NewReader(c.body))
		req.Header.Set("Authorization", "Bearer "+at)
		req.Header.Set("Content-Type", "application/json")
		r, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 403 {
			t.Errorf("%s /admin/realms/deck%s сервисной учётной записью: HTTP %d, ожидался 403", c.method, c.path, r.StatusCode)
		}
	}

	bad := &KeycloakAdmin{BaseURL: base, Realm: "deck", ClientID: "deck-control-plane", ClientSecret: "wrong", HTTP: hc}
	if err := bad.EnsureUser(ctx, "other"); err == nil {
		t.Fatal("с неверным секретом пользователь создан")
	}
}
