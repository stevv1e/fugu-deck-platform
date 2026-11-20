// control-plane Fugu Deck. Настройки — переменные окружения (kubernetes/deck/services/control-plane.yaml).
package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	cp "controlplane"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func must(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("не задана переменная %s", name)
	}
	return v
}

// hpkePublic приводит публичный ключ keyguard к виду, который ждёт приложение: base64url без дополнения.
// scripts/keyguard-hpke-init.sh печатает обычный base64 — принимаем оба вида и проверяем, что это точка P-256.
func hpkePublic(v string) string {
	v = strings.TrimSpace(v)
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(v, "="))
	}
	if err != nil || len(raw) != 65 || raw[0] != 4 {
		log.Fatal("DECK_HPKE_PUBLIC: нужна несжатая точка P-256 (65 байт) в base64 — файл ~/.deck/<окружение>/keyguard-hpke.pub")
	}
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		log.Fatalf("DECK_HPKE_PUBLIC: точка не на кривой P-256: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	domain := must("DECK_DOMAIN") // базовый домен окружения: api.<домен>, id.<домен>, join.<домен>
	hc := &http.Client{Timeout: 20 * time.Second}

	var store cp.Store
	if env("DECK_STATE", "postgres") == "memory" {
		logger.Print("event=state.memory ВНИМАНИЕ: приглашения в памяти и теряются при перезапуске — только для стендов")
		store = cp.NewMemStore()
	} else {
		dsn := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password='%s' sslmode=%s",
			must("DECK_DB_HOST"), env("DECK_DB_PORT", "5432"), env("DECK_DB_NAME", "controlplane"), must("DB_USER"),
			strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(must("DB_PASSWORD")), env("DECK_DB_SSLMODE", "require"))
		pg, err := cp.OpenPG(dsn)
		if err != nil {
			log.Fatalf("Postgres: %v", err)
		}
		store = pg
	}

	// Сон пространств по неактивности: "60m"; "0" или пусто — не усыплять.
	sleepAfter, err := time.ParseDuration(env("DECK_SLEEP_AFTER", "0"))
	if err != nil || sleepAfter < 0 || (sleepAfter > 0 && sleepAfter < 5*time.Minute) {
		log.Fatalf("DECK_SLEEP_AFTER: ожидается длительность не меньше 5m (или 0), получено %q", os.Getenv("DECK_SLEEP_AFTER"))
	}

	// Удаление аккаунтов по неактивности: дней без входа; 0 — выключено (по умолчанию 30, как в архитектуре).
	inactiveDays, err := strconv.Atoi(env("DECK_INACTIVE_DAYS", "30"))
	if err != nil || inactiveDays < 0 || (inactiveDays > 0 && inactiveDays < 8) {
		log.Fatalf("DECK_INACTIVE_DAYS: ожидается 0 или число дней не меньше 8, получено %q", os.Getenv("DECK_INACTIVE_DAYS"))
	}

	s := &cp.Server{
		Cfg: cp.Config{
			APIURL: "https://api." + domain, JoinURL: "https://join." + domain,
			Issuer:  "https://id." + domain + "/realms/" + env("DECK_REALM", "deck"),
			HPKEPub: hpkePublic(must("DECK_HPKE_PUBLIC")), CookieDomain: domain,
			InviteTTL: 24 * time.Hour, GateTTL: 30 * time.Minute, SleepAfter: sleepAfter,
			AppLatest: os.Getenv("DECK_APP_LATEST"), AppURL: os.Getenv("DECK_APP_URL"),
			DriveClientID: os.Getenv("DECK_GOOGLE_OAUTH_CLIENT_ID"),
			InactiveDays:  inactiveDays,
		},
		Store: store,
		KG: &cp.KeyguardHTTP{URL: must("DECK_KEYGUARD_URL"), HTTP: hc,
			TokenPath: env("DECK_KEYGUARD_TOKEN_PATH", "/var/run/secrets/keyguard/token")},
		Users: &cp.KeycloakAdmin{BaseURL: must("DECK_KEYCLOAK_URL"), Realm: env("DECK_REALM", "deck"), HTTP: hc,
			ClientID: env("DECK_KEYCLOAK_CLIENT_ID", "deck-control-plane"), ClientSecret: must("KEYCLOAK_CLIENT_SECRET")},
		Keys: &cp.KeySet{HTTP: hc,
			URL: must("DECK_KEYCLOAK_URL") + "/realms/" + env("DECK_REALM", "deck") + "/protocol/openid-connect/certs"},
		Log: logger,
	}
	s.RevokedList = cp.KeyguardRevoked(s.KG)
	// Серверы пользователей — через ssh-gateway (свой токен ServiceAccount с audience=ssh-gateway).
	if u := os.Getenv("DECK_SSH_GATEWAY_URL"); u != "" {
		s.SSH = &cp.KeyguardHTTP{URL: u, HTTP: hc, TokenPath: env("DECK_SSH_GATEWAY_TOKEN_PATH", "/var/run/secrets/ssh-gateway/token")}
	}
	// Пространства: объекты Space в API Kubernetes. Вне кластера (стенды) эта часть API выключена.
	if spaces, err := cp.InClusterSpaces(env("DECK_SPACES_NAMESPACE", "deck-system")); err == nil {
		s.Spaces = spaces
		go s.RunActivity(context.Background()) // на каждой реплике: активность пространств видна всем (D73)
		if s.Cfg.SleepAfter > 0 {
			go s.RunSleeper(context.Background(), time.Minute)
		}
		// Push-уведомления: ключ сервисного аккаунта Firebase (секрет fcm-credentials). Нет файла — выключены.
		if path := env("DECK_FCM_CREDENTIALS", "/var/run/secrets/fcm/credentials.json"); path != "" {
			if fcm, err := cp.LoadFCM(path, hc); err == nil {
				s.Push = fcm
				logger.Printf("event=push.enabled project=%s", fcm.ProjectID)
				go s.RunPush(context.Background(), 5*time.Second)
			} else {
				logger.Printf("event=push.disabled reason=%q", err.Error())
			}
		}
	} else {
		logger.Printf("event=spaces.disabled reason=%q", err.Error())
	}
	if _, err := url.Parse(s.Cfg.Issuer); err != nil {
		log.Fatalf("DECK_DOMAIN: %v", err)
	}

	servers := []*http.Server{
		{Addr: env("DECK_LISTEN", ":8080"), Handler: s.PublicHandler()},
		{Addr: env("DECK_LISTEN_AUTH", ":8081"), Handler: s.AuthHandler()},
		{Addr: env("DECK_LISTEN_ADMIN", ":8082"), Handler: s.AdminHandler()},
	}
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		srv.ReadHeaderTimeout = 10 * time.Second
		srv.ReadTimeout = 30 * time.Second
		if srv.Addr == env("DECK_LISTEN", ":8080") {
			// Через этот вход приложение загружает вложения в пространство (до ~11 МБ в JSON) — по мобильной сети
			// это дольше полминуты. Заголовки по-прежнему обязаны прийти за 10 секунд.
			srv.ReadTimeout = 3 * time.Minute
		}
		srv.IdleTimeout = 2 * time.Minute
		go func(srv *http.Server) { errc <- srv.ListenAndServe() }(srv)
		logger.Printf("event=listen addr=%s", srv.Addr)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("сервер: %v", err)
		}
	case <-stop:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		srv.Shutdown(ctx)
	}
}
