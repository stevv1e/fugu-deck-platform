// keyguard — единственный читатель ключей API (architecture.md, 5). Конфигурация — переменные окружения
// из kubernetes/deck/services/keyguard.yaml. Слушает :8080; /healthz — жив, /readyz — OpenBao доступен и есть ключ HPKE.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	kg "keyguard"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// baoLogin — вход в OpenBao по проецируемому токену (audience=openbao), кэш до истечения аренды.
type baoLogin struct {
	addr, role, jwtPath string
	hc                  *http.Client
	mu                  sync.Mutex
	tok                 string
	exp                 time.Time
}

func (b *baoLogin) Token(ctx context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tok != "" && time.Now().Before(b.exp) {
		return b.tok, nil
	}
	jwt, err := os.ReadFile(b.jwtPath)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{"role": b.role, "jwt": strings.TrimSpace(string(jwt))})
	req, _ := http.NewRequestWithContext(ctx, "POST", b.addr+"/v1/auth/kubernetes/login", bytes.NewReader(body))
	r, err := b.hc.Do(req)
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
	if json.NewDecoder(r.Body).Decode(&out) != nil || out.Auth.ClientToken == "" {
		return "", fmt.Errorf("openbao login: %d", r.StatusCode)
	}
	b.tok = out.Auth.ClientToken
	b.exp = time.Now().Add(time.Duration(out.Auth.LeaseDuration) * time.Second * 8 / 10)
	return b.tok, nil
}

// loadHPKE — закрытый ключ HPKE из deck/keyguard/hpke (hex). Публичная часть зашита в приложение.
func loadHPKE(ctx context.Context, addr string, login *baoLogin, hc *http.Client) (*ecdh.PrivateKey, error) {
	tok, err := login.Token(ctx)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", addr+"/v1/deck/data/keyguard/hpke", nil)
	req.Header.Set("X-Vault-Token", tok)
	r, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var out struct {
		Data struct {
			Data struct {
				Private string `json:"private_hex"`
			} `json:"data"`
		} `json:"data"`
	}
	if json.NewDecoder(r.Body).Decode(&out) != nil || out.Data.Data.Private == "" {
		return nil, fmt.Errorf("нет ключа HPKE в deck/keyguard/hpke (%d)", r.StatusCode)
	}
	raw, err := hex.DecodeString(out.Data.Data.Private)
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPrivateKey(raw)
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	baoAddr := env("DECK_OPENBAO_ADDR", "http://openbao.deck-secrets.svc.cluster.local:8200")
	hc := &http.Client{Timeout: 10 * time.Second}
	login := &baoLogin{addr: baoAddr, role: env("DECK_OPENBAO_ROLE", "keyguard"), jwtPath: env("DECK_OPENBAO_JWT", "/var/run/secrets/openbao/token"), hc: hc}

	caPEM, _ := os.ReadFile(saDir + "/ca.crt")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	apiHC := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	api := "https://" + env("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc") + ":" + env("KUBERNETES_SERVICE_PORT", "443")

	now := time.Now
	ultra := kg.Price{InPerM: 5, OutPerM: 30, LongAbove: 272_000, LongIn: 10, LongOut: 45}
	srv := &kg.Server{
		Providers: map[string]*kg.Provider{ // цены — USD за 1M токенов (fugu-deck-summary.md); модели без цены не пропускаются
			"anthropic": {Name: "anthropic", BaseURL: env("DECK_UPSTREAM_ANTHROPIC", "https://api.anthropic.com"), Path: "/v1/messages", ProbePath: "/v1/models",
				AuthHeader: "x-api-key", Style: "anthropic", Prices: map[string]kg.Price{
					"claude-fable-5-2": {InPerM: 8, OutPerM: 40}, "claude-opus-5-5": {InPerM: 4, OutPerM: 20},
					"claude-sonnet-5-5": {InPerM: 2, OutPerM: 10}, "claude-haiku-5-5": {InPerM: 0.1, OutPerM: 0.5},
					"claude-sonnet-5": {InPerM: 2, OutPerM: 10}, "claude-haiku-4-5": {InPerM: 1, OutPerM: 5}}},
			"sakana": {Name: "sakana", BaseURL: env("DECK_UPSTREAM_SAKANA", "https://api.sakana.ai"), Path: "/v1/chat/completions", ProbePath: "/v1/models",
				AuthHeader: "authorization", Style: "openai",
				// Цены — console.sakana.ai/pricing (сверено 18.10.2026). Ultra (v1.0, v1.1, v2.0): $5/$30, а запрос с
				// контекстом больше 272K — целиком $10/$45. Namazu: размышления считаются как вывод. Имена без версии —
				// псевдонимы текущих версий. У базового Fugu (цена зависит от нижележащей модели) и Cyber (по запросу)
				// опубликованной цены нет: расход по ним — по самой высокой ставке Sakana (учёт может завысить трату,
				// но не занизить). Уточнить — DECK_PRICES_SAKANA.
				Prices: map[string]kg.Price{
					"fugu-max-v1.0": {InPerM: 2, OutPerM: 6}, "fugu-max": {InPerM: 2, OutPerM: 6},
					"fugu-ultra-v2.0": ultra, "fugu-ultra": ultra, "fugu-ultra-v1.0": ultra, "fugu-ultra-v1.1": ultra,
					"sakana-namazu-v1.0": {InPerM: 0.95, OutPerM: 4}, "sakana-namazu": {InPerM: 0.95, OutPerM: 4},
					"fugu": {InPerM: 10, OutPerM: 45}, "fugu-cyber-v1.0": {InPerM: 10, OutPerM: 45}, "fugu-cyber": {InPerM: 10, OutPerM: 45}}},
			// DeepSeek (api-docs.deepseek.com/quick_start/pricing, 15.10.2026): днём цена вдвое выше, чем ночью, —
			// считаем по дневной (вход без кэша): учёт может завысить трату, но не занизить. Размышления — как вывод.
			"deepseek": {Name: "deepseek", BaseURL: env("DECK_UPSTREAM_DEEPSEEK", "https://api.deepseek.com"), Path: "/chat/completions", ProbePath: "/models",
				AuthHeader: "authorization", Style: "openai",
				Prices: map[string]kg.Price{
					"deepseek-flash": {InPerM: 0.3, OutPerM: 1.2}, "deepseek-v4-flash": {InPerM: 0.3, OutPerM: 1.2},
					"deepseek-v4-pro": {InPerM: 1.32, OutPerM: 3.96}}},
			"openai": {Name: "openai", BaseURL: env("DECK_UPSTREAM_OPENAI", "https://api.openai.com"), Path: "/v1/chat/completions", ProbePath: "/v1/models",
				AuthHeader: "authorization", Style: "openai", MediaPerMinute: map[string]float64{"gpt-4o-transcribe-diarize": 0.01},
				ImagePerImage: map[string]float64{"gpt-image-2.5-flare": 0.25, "gpt-image-2.5-sunburst": 0.25}, Prices: map[string]kg.Price{
					"gpt-6.2-astra": {InPerM: 8, OutPerM: 40}, "gpt-6.2-sol": {InPerM: 2, OutPerM: 10},
					"gpt-6.1-terra": {InPerM: 1, OutPerM: 5}, "gpt-6-luna": {InPerM: 0.1, OutPerM: 0.5}}},
			"xai": {Name: "xai", BaseURL: env("DECK_UPSTREAM_XAI", "https://api.x.ai"), Path: "/v1/chat/completions", ProbePath: "/v1/models",
				AuthHeader: "authorization", Style: "openai", Prices: map[string]kg.Price{"grok-4.7": {InPerM: 2, OutPerM: 6}}},
			"google": {Name: "google", BaseURL: env("DECK_UPSTREAM_GOOGLE", "https://generativelanguage.googleapis.com"), Path: "/v1beta/openai/chat/completions", ProbePath: "/v1beta/models",
				ProbeAuthHeader: "x-goog-api-key", AuthHeader: "authorization", Style: "openai",
				MediaPerMinute: map[string]float64{"gemini-3.8-flash": 0.01, "gemini-3.5-flash-lite": 0.01},
				ImagePerImage:  map[string]float64{"gemini-3.1-flash-lite-image": 0.04, "gemini-nano-banana-2.1": 0.04}, Prices: map[string]kg.Price{
					"gemini-4-carbon": {InPerM: 4, OutPerM: 20}, "gemini-4-argon": {InPerM: 4, OutPerM: 20},
					"gemini-4-hydrogen": {InPerM: 1.5, OutPerM: 7.5}, "gemini-3.8-flash": {InPerM: 0.75, OutPerM: 3.75},
					"gemini-3.5-flash-lite": {InPerM: 0.3, OutPerM: 2.5}}},
			// Kimi Code оплачивается подпиской, а не за токены: нулевые ставки сохраняют учёт usage без вымышленного расхода.
			"kimi": {Name: "kimi", BaseURL: env("DECK_UPSTREAM_KIMI", "https://api.kimi.ai"), Path: "/coding/v1/chat/completions", ProbePath: "/coding/v1/models",
				AuthHeader: "authorization", Style: "openai", Prices: map[string]kg.Price{
					"k3.1-pro": {}, "k3.1-pro-highspeed": {}, "k3": {}, "k3-256k": {}, "kimi-for-coding": {}, "kimi-for-coding-highspeed": {}}},
			"moonshot": {Name: "moonshot", BaseURL: env("DECK_UPSTREAM_MOONSHOT", "https://api.moonshot.ai"), Path: "/v1/chat/completions", ProbePath: "/v1/models",
				AuthHeader: "authorization", Style: "openai", Prices: map[string]kg.Price{
					"kimi-k3.1-pro": {InPerM: 2, OutPerM: 10}, "kimi-k3.1-pro-highspeed": {InPerM: 4, OutPerM: 20}, "kimi-k3": {InPerM: 3, OutPerM: 15}}},
			"qwen": {Name: "qwen", BaseURL: env("DECK_UPSTREAM_QWEN", "https://dashscope-intl.aliyuncs.com"), Path: "/compatible-mode/v1/chat/completions", ProbePath: "/compatible-mode/v1/models",
				AuthHeader: "authorization", Style: "openai", Prices: map[string]kg.Price{
					"qwen4-max": {InPerM: 1.5, OutPerM: 4.5}, "qwen3.8-max": {InPerM: 2, OutPerM: 6}, "qwen3.8-flash": {InPerM: 0.16, OutPerM: 0.47}}},
			"mistral": {Name: "mistral", BaseURL: env("DECK_UPSTREAM_MISTRAL", "https://api.mistral.ai"), Path: "/v1/chat/completions", ProbePath: "/v1/models",
				AuthHeader: "authorization", Style: "openai", Prices: map[string]kg.Price{
					"mistral-large-4": {InPerM: 0.7, OutPerM: 2.1}, "mistral-medium-3.5": {InPerM: 1.5, OutPerM: 7.5}, "mistral-small-latest": {InPerM: 0.15, OutPerM: 0.6}}},
			"minimax": {Name: "minimax", BaseURL: env("DECK_UPSTREAM_MINIMAX", "https://api.minimax.io"), Path: "/v1/chat/completions", ProbePath: "/v1/models",
				AuthHeader: "authorization", Style: "openai", Prices: map[string]kg.Price{
					"MiniMax-M3.1-Flash": {InPerM: 0.15, OutPerM: 0.6},
					"MiniMax-M3":         {InPerM: 0.3, OutPerM: 1.2, LongAbove: 512_000, LongIn: 0.6, LongOut: 2.4}}},
			"zai": {Name: "zai", BaseURL: env("DECK_UPSTREAM_ZAI", "https://api.z.ai"), Path: "/api/paas/v4/chat/completions", ProbePath: "/api/paas/v4/models",
				AuthHeader: "authorization", Style: "openai", Prices: map[string]kg.Price{
					"glm-5.3": {InPerM: 1.4, OutPerM: 4.4}, "glm-5.3-flash": {InPerM: 0.15, OutPerM: 0.5},
					"glm-5.3-flashx": {InPerM: 0.37, OutPerM: 1.25}, "glm-4.7": {InPerM: 0.6, OutPerM: 2.2}}},
		},
		Store:    &kg.BaoStore{Addr: baoAddr, Mount: "deck", HTTP: hc, Token: login.Token},
		Verifier: &kg.Verifier{Devices: kg.NewDevices(), Nonces: kg.NewNonces(), Now: now},
		Auth: &kg.TokenReviewAuth{APIServer: api, HTTP: apiHC, Audience: env("DECK_TOKEN_AUDIENCE", "keyguard"),
			Token: func() (string, error) {
				b, err := os.ReadFile(saDir + "/token")
				return strings.TrimSpace(string(b)), err
			}},
		Ledger: kg.NewLedger(), Grants: kg.NewGrants(), Upstream: &http.Client{Timeout: 15 * time.Minute},
		Log: logger, Now: now, MaxBody: 32 << 20, ControlPlane: kg.Caller{Namespace: "deck-system", ServiceAccount: "control-plane"},
		ActionVerifiers: map[kg.Caller][]string{
			{Namespace: "deck-system", ServiceAccount: "space-operator"}: {"space_delete", "account_delete"},
			{Namespace: "deck-system", ServiceAccount: "control-plane"}:  {"invite_create", "role_change", "pair_approve"},
			{Namespace: "deck-ssh", ServiceAccount: "ssh-gateway"}:       {"ssh_write", "ssh_danger", "server_add", "agent_rights"},
		},
	}
	for name, p := range srv.Providers {
		if raw := os.Getenv("DECK_PROXY_" + strings.ToUpper(name)); raw != "" {
			client, err := kg.NewProviderProxyClient(srv.Upstream, raw)
			if err != nil {
				logger.Fatalf("event=config.error provider=%s proxy=invalid", name)
			}
			p.HTTP = client
			logger.Printf("event=provider.proxy provider=%s", name)
		}
	}
	// Регистрация устройств (Keycloak + DPoP + подпись) и сертификаты для mTLS (OpenBao pki-device).
	if iss := os.Getenv("DECK_KEYCLOAK_ISSUER"); iss != "" {
		srv.Enroll = &kg.EnrollConfig{Issuer: iss, ClientID: "deck-app", HTTP: hc,
			JWKSURL:       env("DECK_KEYCLOAK_JWKS", iss+"/protocol/openid-connect/certs"),
			EnrollURL:     os.Getenv("DECK_ENROLL_URL"),
			StatusURL:     os.Getenv("DECK_ENROLL_STATUS_URL"),
			Admins:        strings.Split(env("DECK_ADMINS", ""), ","),
			BootstrapUser: os.Getenv("DECK_BOOTSTRAP_ADMIN"),
			// восстановление администратора без устройств — включать в git на время и снимать сразу после
			Recover: os.Getenv("DECK_BOOTSTRAP_RECOVER") == "1"}
		srv.Certs = &kg.BaoPKI{Addr: baoAddr, Mount: "pki-device", Role: "device", TTL: env("DECK_DEVICE_CERT_TTL", "720h"), Token: login.Token, HTTP: hc}
	}
	// Аттестация устройств (attest.go): DECK_ATTESTATION=off|optional|required|vouched. Платформа без своих настроек
	// не принимается. vouched — устройство без аттестации активирует только подпись аттестованного устройства.
	if mode := env("DECK_ATTESTATION", "optional"); mode != "off" {
		if mode != "optional" && mode != "required" && mode != "vouched" {
			logger.Fatalf("event=config.error DECK_ATTESTATION=%q: нужно off, optional, required или vouched", mode)
		}
		ap := kg.NewAttestPolicy(mode)
		ap.AndroidPackage = os.Getenv("DECK_ANDROID_PACKAGE")
		for _, h := range strings.Split(os.Getenv("DECK_ANDROID_CERT_SHA256"), ",") {
			if h = strings.ReplaceAll(strings.TrimSpace(h), ":", ""); h != "" {
				d, err := hex.DecodeString(h)
				if err != nil || len(d) != 32 {
					logger.Fatalf("event=config.error DECK_ANDROID_CERT_SHA256: нужен SHA-256 сертификата подписи в hex")
				}
				ap.AndroidCertDigests = append(ap.AndroidCertDigests, d)
			}
		}
		ap.AppleAppID = os.Getenv("DECK_APPLE_APP_ID")
		ap.AllowDevelopment = os.Getenv("DECK_APPLE_ATTEST_DEVELOPMENT") == "1"
		ap.AllowUnlocked = os.Getenv("DECK_ATTEST_ALLOW_UNLOCKED") == "1"
		if (mode == "required" || mode == "vouched") && ap.AndroidPackage == "" && ap.AppleAppID == "" {
			logger.Fatalf("event=config.error DECK_ATTESTATION=%s, но не задана ни одна платформа (DECK_ANDROID_PACKAGE + DECK_ANDROID_CERT_SHA256, DECK_APPLE_APP_ID)", mode)
		}
		srv.Attest = ap
		logger.Printf("event=attestation mode=%s android=%t ios=%t", mode, ap.AndroidPackage != "" && len(ap.AndroidCertDigests) > 0, ap.AppleAppID != "")
	}
	srv.Providers["github"] = kg.GitHubProvider(env("DECK_UPSTREAM_GITHUB", "https://api.github.com"))
	srv.Providers["gitlab"] = kg.GitLabProvider(env("DECK_UPSTREAM_GITLAB", "https://gitlab.com"))
	srv.Providers["google_drive"] = kg.GoogleDriveProvider(env("DECK_UPSTREAM_GOOGLE_DRIVE", "https://www.googleapis.com"),
		os.Getenv("DECK_GOOGLE_OAUTH_CLIENT_ID"), os.Getenv("DECK_GOOGLE_OAUTH_CLIENT_SECRET"), os.Getenv("DECK_GOOGLE_OAUTH_REDIRECT"))
	// Любой каталог можно дополнить или заменить: DECK_PRICES_OPENAI="model=in:out,model2=in:out" и т.п.
	for prov, p := range srv.Providers {
		if p.Prices == nil {
			continue
		}
		name := "DECK_PRICES_" + strings.ToUpper(prov)
		for _, e := range strings.Split(os.Getenv(name), ",") {
			var m string
			var in, out float64
			if n, _ := fmt.Sscanf(strings.Replace(strings.Replace(e, "=", " ", 1), ":", " ", 1), "%s %g %g", &m, &in, &out); n == 3 && in > 0 && out > 0 {
				p.Prices[m] = kg.Price{InPerM: in, OutPerM: out}
			}
		}
	}

	// Состояние (устройства, nonce, разрешения, расходы) — в Postgres. Без базы keyguard не стартует: в памяти оно
	// не переживает перезапуск (повтор подписей, обнуление лимитов). DECK_STATE=memory — только для стендов.
	var state *kg.PGState
	switch {
	case os.Getenv("DECK_DB_HOST") != "":
		dsn := url.URL{Scheme: "postgres", User: url.UserPassword(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD")),
			Host: os.Getenv("DECK_DB_HOST") + ":" + env("DECK_DB_PORT", "5432"), Path: "/" + env("DECK_DB_NAME", "keyguard"),
			RawQuery: url.Values{"sslmode": {env("DECK_DB_SSLMODE", "require")}, "connect_timeout": {"5"},
				"application_name": {"keyguard"}}.Encode()}
		if ca := os.Getenv("DECK_DB_SSLROOTCERT"); ca != "" {
			q := dsn.Query()
			q.Set("sslrootcert", ca)
			dsn.RawQuery = q.Encode()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		var err error
		state, err = kg.OpenPGState(ctx, dsn.String(),
			func() {
				logger.Printf("event=state.waiting reason=\"другой keyguard держит блокировку экземпляра\"")
			},
			func(err error) { logger.Fatalf("event=state.lock_lost err=%q — завершаюсь", err.Error()) })
		if err == nil {
			err = srv.Restore(ctx, state)
		}
		cancel()
		if err != nil {
			logger.Fatalf("event=state.unavailable err=%q", err.Error())
		}
	case os.Getenv("DECK_STATE") == "memory":
		logger.Printf("event=state.memory warning=\"состояние только в памяти: после перезапуска возможен повтор подписей и обнуление лимитов\"")
	default:
		logger.Fatalf("event=state.unconfigured — задайте DECK_DB_HOST (Postgres) или DECK_STATE=memory (только стенды)")
	}
	// Аварийный отзыв устройств по списку из конфигурации (actions.go, RevokeListed).
	if ids := os.Getenv("DECK_REVOKE_DEVICES"); ids != "" {
		revoked, unknown, err := srv.Verifier.Devices.RevokeListed(strings.Split(ids, ","))
		for _, id := range revoked {
			logger.Printf("event=device.revoke device=%s by=config", id)
		}
		for _, id := range unknown {
			logger.Printf("event=device.revoke_unknown device=%s by=config", id)
		}
		if err != nil {
			logger.Fatalf("event=state.unavailable op=device.revoke err=%q", err.Error())
		}
	}

	var ready sync.Map
	hpkeLoaded := false // меняется только в этой горутине
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if !hpkeLoaded {
				if k, err := loadHPKE(ctx, baoAddr, login, hc); err == nil {
					srv.SetHPKEKey(k)
					hpkeLoaded = true
					logger.Printf("event=hpke.loaded")
				} else {
					logger.Printf("event=hpke.unavailable err=%q", err.Error())
				}
			}
			_, err := login.Token(ctx)
			if err == nil && state != nil {
				if err = state.Ping(ctx); err != nil {
					logger.Printf("event=state.error op=ping err=%q", err.Error())
				}
			}
			ready.Store("ok", err == nil && hpkeLoaded)
			cancel()
			time.Sleep(15 * time.Second)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/", srv.Handler())
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if v, _ := ready.Load("ok"); v == true {
			w.Write([]byte("ok"))
			return
		}
		http.Error(w, "openbao, ключ HPKE или база состояния недоступны", 503)
	})
	hs := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	logger.Printf("event=start addr=:8080")
	log.Fatal(hs.ListenAndServe())
}
