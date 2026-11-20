package keyguard

// Живой kube-apiserver (k3s): keyguard опознаёт пространство по проецируемому токену ServiceAccount через TokenReview.
// Пропускается без KUBECONFIG. KUBECTL — команда kubectl (по умолчанию "/tmp/bin/k3s kubectl").

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func kubectl(t *testing.T, args ...string) (string, error) {
	base := strings.Fields(envOr("KUBECTL", "/tmp/bin/k3s kubectl"))
	out, err := exec.Command(base[0], append(base[1:], args...)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestIntegration_TokenReview(t *testing.T) {
	if os.Getenv("KUBECONFIG") == "" {
		t.Skip("нет KUBECONFIG")
	}
	if _, err := kubectl(t, "get", "--raw", "/version"); err != nil {
		t.Skip("API недоступен")
	}
	op := []string{"--as=system:serviceaccount:argocd:argocd-application-controller", "--as-group=system:serviceaccounts"}
	// SA, от имени которого keyguard вызывает TokenReview (в бою — сам keyguard; его токен человеку не выпустить)
	kubectl(t, append([]string{"-n", "default", "create", "sa", "kg-reviewer"}, op...)...)
	kubectl(t, append([]string{"create", "clusterrolebinding", "kg-reviewer", "--clusterrole=system:auth-delegator", "--serviceaccount=default:kg-reviewer"}, op...)...)
	kubectl(t, append([]string{"-n", "deck-u-anna", "create", "sa", "space"}, op...)...)
	kubectl(t, append([]string{"-n", "deck-t-shop", "create", "sa", "space"}, op...)...)

	own, err := kubectl(t, "-n", "default", "create", "token", "kg-reviewer", "--duration=1h")
	if err != nil {
		t.Fatal(own)
	}
	srv, _ := kubectl(t, "config", "view", "--raw", "-o", "jsonpath={.clusters[0].cluster.server}")
	caB64, _ := kubectl(t, "config", "view", "--raw", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	ca, _ := base64.StdEncoding.DecodeString(caB64)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	auth := &TokenReviewAuth{APIServer: srv, HTTP: hc, Audience: "keyguard", Token: func() (string, error) { return own, nil }}
	ctx := context.Background()
	c := &check{t: t}
	tok := func(ns, sa, aud string) string {
		x, err := kubectl(t, "-n", ns, "create", "token", sa, "--audience="+aud, "--duration=10m")
		if err != nil {
			t.Fatal(x)
		}
		return x
	}

	tAnna := tok("deck-u-anna", "space", "keyguard")
	got, err := auth.Authenticate(ctx, tAnna)
	c.ok("T1 токен пространства Анны (aud=keyguard) → deck-u-anna/space", err == nil && got == Caller{"deck-u-anna", "space"}, got, err)
	_, err = auth.Authenticate(ctx, tok("deck-u-anna", "space", "ssh-gateway"))
	c.ok("T2 токен для ssh-gateway не годится для keyguard (audience)", err != nil, err)
	_, err = auth.Authenticate(ctx, tok("deck-u-anna", "space", "https://kubernetes.default.svc.cluster.local"))
	c.ok("T3 обычный токен API (без aud keyguard) не годится", err != nil, err)
	_, err = auth.Authenticate(ctx, tAnna[:len(tAnna)-4]+"AAAA")
	c.ok("T4 подделанная подпись токена — отказ", err != nil, err)
	_, err = auth.Authenticate(ctx, "garbage")
	c.ok("T5 мусор вместо токена — отказ", err != nil, err)
	_, err = auth.Authenticate(ctx, own)
	c.ok("T6 токен без aud keyguard (собственный токен keyguard) — отказ", err != nil, err)

	// после удаления ServiceAccount связанный токен перестаёт действовать (свежий, не из кэша)
	kubectl(t, append([]string{"-n", "deck-u-anna", "create", "sa", "tmp"}, op...)...)
	tTmp := tok("deck-u-anna", "tmp", "keyguard")
	kubectl(t, append([]string{"-n", "deck-u-anna", "delete", "sa", "tmp"}, op...)...)
	time.Sleep(1 * time.Second)
	_, err = auth.Authenticate(ctx, tTmp)
	c.ok("T7 токен удалённого ServiceAccount — отказ", err != nil, err)

	// полный путь: настоящий токен пространства как «ключ API» в SDK → keyguard → провайдер получает ключ Анны
	k := newRig(t)
	k.seed()
	k.srv.Auth = auth
	st, _ := k.do("POST", "/llm/anthropic/v1/messages", tAnna, []byte(`{"model":"claude-x","max_tokens":10,"messages":[]}`), nil)
	up, _ := k.anth.last()
	c.ok("T8 настоящий токен пространства → провайдер получил ключ Анны, а токен не ушёл наружу",
		st == 200 && up.Header.Get("x-api-key") == "sk-ant-ANNA-0123456789" && !strings.Contains(strings.Join(up.Header.Values("Authorization"), ""), tAnna))
	tShop := tok("deck-t-shop", "space", "keyguard")
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", tShop, []byte(`{"model":"claude-x","max_tokens":10,"messages":[]}`), nil)
	c.ok("T9 общее пространство без разрешения спонсора не получает ничей ключ", st == 403, st)
	t.Logf("TokenReview: %d/%d", c.n, c.n+c.f)
}
