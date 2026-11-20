package keyguard

// Живой OpenBao: выпуск сертификата устройства через pki-device с ролью как в terraform/openbao.
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestIntegration_DeviceCertPKI(t *testing.T) {
	bin := envOr("BAO_BIN", "/tmp/bin/bao")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("нет OpenBao")
	}
	const addr, root = "http://127.0.0.1:8356", "root-pki"
	cmd := exec.Command(bin, "server", "-dev", "-dev-root-token-id="+root, "-dev-listen-address=127.0.0.1:8356")
	cmd.Start()
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	call := func(method, path string, body any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, addr+"/v1/"+path, strings.NewReader(string(b)))
		req.Header.Set("X-Vault-Token", root)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil
		}
		defer r.Body.Close()
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		return r.StatusCode, m
	}
	for i := 0; i < 50; i++ {
		if st, _ := call("GET", "sys/health", nil); st == 200 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	call("POST", "sys/mounts/pki-device", map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "8760h"}})
	call("POST", "pki-device/root/generate/internal", map[string]any{"common_name": "Fugu Deck Device CA", "key_type": "ec", "key_bits": 256, "ttl": "8760h"})
	role := func(useCSRCN bool) {
		call("POST", "pki-device/roles/device", map[string]any{"ttl": "720h", "max_ttl": "720h", "key_type": "ec", "key_bits": 256,
			"allow_any_name": true, "enforce_hostnames": false, "allow_ip_sans": false, "allow_localhost": false,
			"use_csr_common_name": useCSRCN, "use_csr_sans": false, "require_cn": true, "cn_validations": []string{"disabled"},
			"server_flag": false, "client_flag": true})
	}
	c := &check{t: t}
	pki := &BaoPKI{Addr: addr, Mount: "pki-device", Role: "device", TTL: "720h", HTTP: http.DefaultClient,
		Token: func(context.Context) (string, error) { return root, nil }}
	sess, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// телефон-злоумышленник вписывает в CSR идентификатор ЧУЖОГО устройства
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "d-victimvictimvic"}}, sess)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	parse := func(p string) *x509.Certificate {
		b, _ := pem.Decode([]byte(p))
		x, _ := x509.ParseCertificate(b.Bytes)
		return x
	}

	role(true) // прежняя роль из terraform
	cp, err := pki.Issue(context.Background(), csr, "d-attackerattack")
	c.ok("P1 прежняя роль (use_csr_common_name=true): CN взят из CSR телефона — подмена удалась (дыра воспроизведена)",
		err == nil && parse(cp).Subject.CommonName == "d-victimvictimvic", err)

	role(false) // исправленная роль
	cp, err = pki.Issue(context.Background(), csr, "d-attackerattack")
	x := parse(cp)
	c.ok("P2 исправленная роль: CN задаёт keyguard (ID устройства), CSR не влияет", err == nil && x.Subject.CommonName == "d-attackerattack", err)
	c.ok("P3 в сертификате ключ сессии телефона", err == nil && x.PublicKey.(*ecdsa.PublicKey).Equal(&sess.PublicKey))
	c.ok("P4 только клиентский сертификат (не годится для сервера)", err == nil && len(x.ExtKeyUsage) == 1 && x.ExtKeyUsage[0] == x509.ExtKeyUsageClientAuth, x.ExtKeyUsage)
	life := x.NotAfter.Sub(x.NotBefore)
	c.ok("P5 срок 30 дней", life > 719*time.Hour && life < 721*time.Hour, life)
	c.ok("P6 нет SAN (только CN)", len(x.DNSNames) == 0 && len(x.IPAddresses) == 0, x.DNSNames)
	t.Logf("PKI устройств: %d/%d", c.n, c.n+c.f)
}
