// ssh-gateway Fugu Deck: выполняет команды агентов на серверах пользователей (docs/ARCHITECTURE-v2.md, раздел 7).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	gw "sshgateway"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func dur(logger *log.Logger, name, def string, min time.Duration) time.Duration {
	d, err := time.ParseDuration(env(name, def))
	if err != nil || d < min {
		logger.Fatalf("%s: ожидается длительность не меньше %s, получено %q", name, min, os.Getenv(name))
	}
	return d
}

func num(logger *log.Logger, name string, def, min int) int {
	n, err := strconv.Atoi(env(name, strconv.Itoa(def)))
	if err != nil || n < min {
		logger.Fatalf("%s: ожидается число не меньше %d, получено %q", name, min, os.Getenv(name))
	}
	return n
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	const sa = "/var/run/secrets/kubernetes.io/serviceaccount"
	ca, err := os.ReadFile(sa + "/ca.crt")
	if err != nil {
		logger.Fatalf("сертификат API Kubernetes: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	apiHC := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	hc := &http.Client{Timeout: 15 * time.Second}

	store, err := gw.OpenFileStore(env("DECK_STATE_FILE", "/var/lib/ssh-gateway/state.json"))
	if err != nil {
		logger.Fatalf("состояние шлюза: %v", err)
	}
	journal, err := gw.OpenFileJournal(env("DECK_JOURNAL_FILE", "/var/lib/ssh-gateway/journal.jsonl"), nil)
	if err != nil {
		logger.Fatalf("журнал команд: %v", err)
	}
	signer := &gw.BaoSigner{Addr: env("DECK_OPENBAO_ADDR", "http://openbao.deck-secrets.svc.cluster.local:8200"),
		Role: env("DECK_OPENBAO_ROLE", "ssh-gateway"), JWTPath: env("DECK_OPENBAO_JWT", "/var/run/secrets/openbao/token"),
		TTL: dur(logger, "DECK_CERT_TTL", "10m", time.Minute), SourceIP: os.Getenv("DECK_EGRESS_IP"), HTTP: hc}
	g := &gw.Gateway{
		Cfg: gw.Config{MaxServers: num(logger, "DECK_MAX_SERVERS", 20, 1), MaxCommandsHour: num(logger, "DECK_MAX_COMMANDS_HOUR", 120, 1)},
		Auth: &gw.TokenReviewAuth{APIServer: "https://" + os.Getenv("KUBERNETES_SERVICE_HOST") + ":" + os.Getenv("KUBERNETES_SERVICE_PORT"),
			HTTP: apiHC, Audience: env("DECK_TOKEN_AUDIENCE", "ssh-gateway"),
			Token: func() (string, error) {
				b, err := os.ReadFile(sa + "/token")
				return strings.TrimSpace(string(b)), err
			}},
		Verify: &gw.KeyguardHTTP{URL: env("DECK_KEYGUARD_URL", "http://keyguard.deck-keys.svc.cluster.local:8080"),
			TokenPath: env("DECK_KEYGUARD_TOKEN_PATH", "/var/run/secrets/keyguard/token"), HTTP: hc},
		Store: store, Signer: signer, Log: logger, Journal: journal,
		ControlPlane: gw.Caller{Namespace: "deck-system", ServiceAccount: "control-plane"},
		Run: &gw.SSHRunner{Signer: signer, Timeout: dur(logger, "DECK_COMMAND_TIMEOUT", "5m", 10*time.Second),
			MaxOutput: num(logger, "DECK_MAX_OUTPUT", 256<<10, 1024)},
	}
	// Владельцы общих пространств — из объектов Space (роль: get spaces в deck-system). Нет доступа — общие не обслуживаются.
	if owners, err := gw.InClusterOwners(env("DECK_SPACES_NAMESPACE", "deck-system")); err == nil {
		g.Owners = owners
	} else {
		logger.Printf("event=teams.disabled reason=%q", err.Error())
	}
	srv := &http.Server{Addr: env("DECK_LISTEN", ":8080"), Handler: g.Handler(), ReadHeaderTimeout: 10 * time.Second}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go func() { <-ctx.Done(); srv.Close() }()
	logger.Printf("event=start addr=%s source_ip=%q", srv.Addr, signer.SourceIP)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("сервер: %v", err)
	}
}
