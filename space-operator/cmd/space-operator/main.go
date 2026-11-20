// space-operator Fugu Deck. Настройки — переменные окружения (kubernetes/deck/services/space-operator.yaml).
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	so "spaceoperator"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	image := os.Getenv("DECK_SPACE_IMAGE")
	if image == "" {
		logger.Fatal("не задана переменная DECK_SPACE_IMAGE")
	}
	kube, err := so.InCluster()
	if err != nil {
		logger.Fatalf("API Kubernetes: %v", err)
	}
	op := &so.Operator{Kube: kube, Namespace: env("DECK_SPACES_NAMESPACE", "deck-system"), Log: logger, Now: time.Now,
		Cfg: so.Config{SpaceImage: image, RuntimeClass: env("DECK_RUNTIME_CLASS", "gvisor"),
			KeyguardURL:   env("DECK_KEYGUARD_URL", "http://keyguard.deck-keys.svc.cluster.local:8080"),
			SquidURL:      env("DECK_SQUID_URL", "http://squid.deck-egress.svc.cluster.local:3128"),
			SSHGatewayURL: os.Getenv("DECK_SSH_GATEWAY_URL"),
			SpaceDNS:      env("DECK_SPACE_DNS", "10.43.0.53"), StorageClass: env("DECK_STORAGE_CLASS", "local-path")}}

	// Удаление пространств: подпись владельца проверяет keyguard, срок до удаления отсчитывает оператор.
	delay, err := time.ParseDuration(env("DECK_DELETE_DELAY", "24h"))
	if err != nil || delay < time.Minute {
		logger.Fatalf("DECK_DELETE_DELAY: ожидается длительность не меньше 1m, получено %q", os.Getenv("DECK_DELETE_DELAY"))
	}
	op.Cfg.DeleteDelay = delay
	if d, err := strconv.Atoi(env("DECK_INACTIVE_DAYS", "30")); err == nil && d >= 0 {
		op.Cfg.InactiveAfter = time.Duration(d) * 24 * time.Hour
	} else {
		logger.Fatalf("DECK_INACTIVE_DAYS: ожидается число дней, получено %q", os.Getenv("DECK_INACTIVE_DAYS"))
	}
	op.Verify = so.KeyguardVerifier(op.Cfg.KeyguardURL, env("DECK_KEYGUARD_TOKEN_PATH", "/var/run/secrets/keyguard/token"),
		&http.Client{Timeout: 15 * time.Second})
	op.Purge = so.KeyguardPurger(op.Cfg.KeyguardURL, env("DECK_KEYGUARD_TOKEN_PATH", "/var/run/secrets/keyguard/token"),
		&http.Client{Timeout: 30 * time.Second})

	// Резервные копии: оператор сам забирает снимки баз пространств и кладёт их в S3. Без настроек — выключены.
	if bucket := os.Getenv("DECK_BACKUP_S3_BUCKET"); bucket != "" {
		every, err := time.ParseDuration(env("DECK_BACKUP_EVERY", "15m"))
		if err != nil || every < time.Minute {
			logger.Fatalf("DECK_BACKUP_EVERY: ожидается длительность не меньше 1m, получено %q", os.Getenv("DECK_BACKUP_EVERY"))
		}
		ak, sk := os.Getenv("DECK_BACKUP_S3_ACCESS_KEY"), os.Getenv("DECK_BACKUP_S3_SECRET_KEY")
		endpoint, region := os.Getenv("DECK_BACKUP_S3_ENDPOINT"), os.Getenv("DECK_BACKUP_S3_REGION")
		if ak == "" || sk == "" || endpoint == "" || region == "" {
			logger.Fatal("резервные копии: заданы не все из DECK_BACKUP_S3_ENDPOINT, _REGION, _ACCESS_KEY, _SECRET_KEY")
		}
		token := so.BackupTokenFunc(sk)
		op.Cfg.BackupToken = token
		op.Backup = &so.Backups{Every: every, Token: token, TmpDir: os.TempDir(), HTTP: &http.Client{Timeout: 5 * time.Minute},
			Store: &so.S3{Endpoint: endpoint, Region: region, Bucket: bucket, AccessKey: ak, SecretKey: sk,
				HTTP: &http.Client{Timeout: 5 * time.Minute}}}
		logger.Printf("event=backup.enabled bucket=%s every=%s", bucket, every)
	} else {
		logger.Print("event=backup.disabled reason=\"не задан DECK_BACKUP_S3_BUCKET\"")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	var ready atomic.Bool
	go func() {
		// первый удачный проход = готов
		for ctx.Err() == nil {
			if err := op.ReconcileAll(ctx); err == nil {
				ready.Store(true)
				break
			} else {
				logger.Printf("event=reconcile.failed err=%q", err.Error())
				time.Sleep(5 * time.Second)
			}
		}
		go op.RunBackups(ctx)
		op.Run(ctx, 15*time.Second)
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "ещё не было удачного прохода", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: env("DECK_LISTEN", ":8081"), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); srv.Close() }()
	logger.Printf("event=start image=%s", image)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("сервер: %v", err)
	}
}
