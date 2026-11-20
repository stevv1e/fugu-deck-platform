package sshgateway

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Настоящий OpenBao (SSH CA, роль agent как в terraform/openbao/main.tf) и настоящий sshd, настроенный командами
// из приложения (TrustedUserCAKeys + AuthorizedPrincipalsFile). Стенд поднимает scripts/sshd_test.sh и задаёт
// GW_BAO_ADDR, GW_BAO_TOKEN, GW_SSHD_HOST, GW_SSHD_PORT, GW_HOST_KEY, GW_PRINCIPAL, GW_SOURCE_IP.
func TestRealOpenBaoAndSSHD(t *testing.T) {
	if os.Getenv("GW_BAO_ADDR") == "" {
		t.Skip("нужен стенд: scripts/sshd_test.sh")
	}
	port, _ := strconv.Atoi(os.Getenv("GW_SSHD_PORT"))
	srv := Server{ID: "prod-1", Host: os.Getenv("GW_SSHD_HOST"), Port: port, User: "deck-agent", HostKey: os.Getenv("GW_HOST_KEY")}
	signer := func(sourceIP string) *BaoSigner {
		return &BaoSigner{Addr: os.Getenv("GW_BAO_ADDR"), StaticToken: os.Getenv("GW_BAO_TOKEN"), TTL: 10 * time.Minute, SourceIP: sourceIP,
			HTTP: &http.Client{Timeout: 10 * time.Second}}
	}
	runner := func(sourceIP string) *SSHRunner {
		return &SSHRunner{Signer: signer(sourceIP), Timeout: 20 * time.Second, MaxOutput: 64 << 10, AllowPrivate: true}
	}
	ctx := context.Background()
	principal := os.Getenv("GW_PRINCIPAL")

	ca, err := signer("").CAPublicKey(ctx)
	if err != nil || !strings.HasPrefix(ca, "ssh-ed25519 ") {
		t.Fatalf("ключ CA: %q %v", ca, err)
	}
	// 1. Сертификат OpenBao на 10 минут принимается sshd; команда выполняется от deck-agent без терминала.
	res, err := runner("").Run(ctx, srv, principal, "id -un; echo строка в stderr >&2; exit 3")
	if err != nil || strings.TrimSpace(res.Stdout) != "deck-agent" || !strings.Contains(res.Stderr, "строка в stderr") || res.ExitCode != 3 {
		t.Fatalf("команда на настоящем sshd: %+v %v", res, err)
	}
	if res, err := runner("").Run(ctx, srv, principal, "test -t 0 && echo tty || echo no-tty"); err != nil || strings.TrimSpace(res.Stdout) != "no-tty" {
		t.Fatalf("терминала быть не должно: %+v %v", res, err)
	}
	// 2. Сертификат с чужим principal (другой агент, другое пространство) sshd не принимает.
	for _, p := range []string{"deck-u-bob-fugu", "deck-agent", "root"} {
		if _, err := runner("").Run(ctx, srv, p, "id"); err == nil || !strings.Contains(err.Error(), "вход по SSH") {
			t.Errorf("principal %s принят: %v", p, err)
		}
	}
	// 3. Привязка к исходящему адресу: сертификат «только с 203.0.113.9» с нашего адреса не работает,
	//    а с нашим настоящим адресом — работает.
	if _, err := runner("203.0.113.9").Run(ctx, srv, principal, "id"); err == nil {
		t.Error("сертификат с чужим source-address принят")
	}
	if ip := os.Getenv("GW_SOURCE_IP"); ip != "" {
		if res, err := runner(ip).Run(ctx, srv, principal, "echo ok"); err != nil || strings.TrimSpace(res.Stdout) != "ok" {
			t.Errorf("сертификат со своим source-address (%s): %+v %v", ip, res, err)
		}
	}
	// 4. Подменённый ключ хоста — не входим.
	bad := srv
	bad.HostKey = "SHA256:" + strings.Repeat("A", 43)
	if _, err := runner("").Run(ctx, bad, principal, "id"); err == nil || !strings.Contains(err.Error(), "ключ хоста") {
		t.Errorf("чужой ключ хоста: %v", err)
	}
	// 5. Зависшая команда обрывается, и процесс на сервере не остаётся висеть.
	r := runner("")
	r.Timeout = 3 * time.Second
	if res, err := r.Run(ctx, srv, principal, "sleep 60"); err != nil || !res.TimedOut {
		t.Errorf("таймаут: %+v %v", res, err)
	}
	// 6. Проброс портов и прочее сертификатом не разрешены: есть только permit-pty.
	crt, err := signer("").Sign(ctx, testPub(t), principal)
	if err != nil {
		t.Fatal(err)
	}
	if ext := certExtensions(t, crt); len(ext) != 1 || ext[0] != "permit-pty" {
		t.Errorf("расширения сертификата: %v", ext)
	}
}
