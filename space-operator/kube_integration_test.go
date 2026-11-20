package spaceoperator

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Тест на настоящем kube-apiserver с правилами допуска платформы: scripts/kube_test.sh поднимает одноразовый k3s,
// ставит CRD, политики и права space-operator и задаёт SO_KUBE_URL и SO_KUBE_TOKEN_FILE (токен ServiceAccount
// space-operator). Объекты Space к этому моменту уже созданы скриптом.
func TestOperatorOnRealAPIServer(t *testing.T) {
	base, tokFile := os.Getenv("SO_KUBE_URL"), os.Getenv("SO_KUBE_TOKEN_FILE")
	if base == "" {
		t.Skip("нужен SO_KUBE_URL (scripts/kube_test.sh)")
	}
	kube := &KubeHTTP{Base: base, TokenPath: tokFile, HTTP: &http.Client{Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}} // одноразовый стенд на 127.0.0.1
	op := &Operator{Kube: kube, Namespace: "deck-system", Log: log.New(io.Discard, "", 0), Now: time.Now,
		Cfg: Config{SpaceImage: "ghcr.io/example/deck-space:test", RuntimeClass: "gvisor",
			KeyguardURL: "http://keyguard.deck-keys.svc.cluster.local:8080", SquidURL: "http://squid.deck-egress.svc.cluster.local:3128",
			SSHGatewayURL: "http://ssh-gateway.deck-ssh.svc.cluster.local:8080",
			SpaceDNS:      "10.43.0.53", StorageClass: "local-path"}}
	// Резервные копии включены: оператор кладёт в пространство Secret с токеном (права — только запись) и
	// монтирует его в под; хранилище здесь в памяти.
	op.Cfg.BackupToken = BackupTokenFunc("integration")
	op.Backup = &Backups{Store: &fakeStore{objs: map[string][]byte{}}, Every: time.Hour, HTTP: http.DefaultClient,
		Token: op.Cfg.BackupToken, TmpDir: t.TempDir()}
	ctx := context.Background()
	for i := 0; i < 2; i++ { // второй проход — проверка, что повторное применение ничего не ломает
		if err := op.ReconcileAll(ctx); err != nil {
			t.Fatal(err)
		}
	}
	get := func(path string) map[string]any {
		t.Helper()
		o, err := kube.Get(ctx, path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return o
	}
	sp := "/apis/deck.fugu/v1alpha1/namespaces/deck-system/spaces/"
	if a := get(sp + "anna"); str(a, "status", "phase") != "Pending" || str(a, "status", "namespace") != "deck-u-anna" {
		t.Fatalf("статус anna: %v", a["status"])
	}
	// чужой ник в имени, командное пространство, без ключа control-plane — не обслуживаются
	for _, bad := range []string{"mallory", "team1", "nokey"} {
		if b := get(sp + bad); str(b, "status", "phase") != "Failed" {
			t.Errorf("%s: phase=%q, ожидался Failed (%v)", bad, str(b, "status", "phase"), b["status"])
		}
	}
	if _, err := kube.Get(ctx, "/api/v1/namespaces/deck-u-bob"); err != ErrNotFound {
		t.Error("для пространства mallory создан namespace чужого пользователя deck-u-bob")
	}
	// общее пространство: свой namespace deck-t-…, владелец в метке, агент знает, что он общий
	if tm := get(sp + "t-shop0001"); str(tm, "status", "phase") != "Pending" || str(tm, "status", "namespace") != "deck-t-shop0001" {
		t.Errorf("общее пространство: %v", tm["status"])
	}
	if tns := get("/api/v1/namespaces/deck-t-shop0001"); str(tns, "metadata", "labels", "deck.fugu/owner") != "anna" {
		t.Errorf("метки namespace общего пространства: %v", tns["metadata"])
	}
	td, _ := json.Marshal(get("/apis/apps/v1/namespaces/deck-t-shop0001/deployments/space")["spec"])
	if !strings.Contains(string(td), `{"name":"SPACE_KIND","value":"team"}`) || !strings.Contains(string(td), `{"name":"SPACE_ID","value":"t-shop0001"}`) {
		t.Errorf("под общего пространства: %s", td)
	}
	// остановленное пространство: всё создано, реплик 0
	if z := get(sp + "zoe"); str(z, "status", "phase") != "Sleeping" {
		t.Errorf("zoe: phase=%q", str(z, "status", "phase"))
	}
	d := get("/apis/apps/v1/namespaces/deck-u-zoe/deployments/space")
	if n, _ := d["spec"].(map[string]any)["replicas"].(float64); n != 0 {
		t.Errorf("zoe: replicas=%v", n)
	}
	// Secret создан, а прочитать его оператор не может (секреты платформы ему не видны по той же причине).
	if _, err := kube.Get(ctx, "/api/v1/namespaces/deck-u-anna/secrets/space-backup"); err == nil || err == ErrNotFound {
		t.Errorf("оператор читает секреты или секрет не создан: %v", err)
	}
	vols, _ := json.Marshal(get("/apis/apps/v1/namespaces/deck-u-anna/deployments/space")["spec"])
	if !strings.Contains(string(vols), `"secretName":"space-backup"`) || !strings.Contains(string(vols), "BACKUP_TOKEN_FILE") {
		t.Errorf("в поде нет токена копирования: %s", vols)
	}
	ns := get("/api/v1/namespaces/deck-u-anna")
	if str(ns, "metadata", "labels", "deck.fugu/space") != "true" || str(ns, "metadata", "labels", "pod-security.kubernetes.io/enforce") != "restricted" {
		t.Errorf("метки namespace: %v", ns["metadata"])
	}
}

// Удаление на настоящем kube-apiserver: поля status принимает схема CRD, прав оператора хватает на namespace
// пространства и объект Space, а правила допуска не дают ему удалить чужой namespace. Запускается после
// TestOperatorOnRealAPIServer (пространство zoe уже создано).
func TestDeletionOnRealAPIServer(t *testing.T) {
	base, tokFile := os.Getenv("SO_KUBE_URL"), os.Getenv("SO_KUBE_TOKEN_FILE")
	if base == "" {
		t.Skip("нужен SO_KUBE_URL (scripts/kube_test.sh)")
	}
	kube := &KubeHTTP{Base: base, TokenPath: tokFile, HTTP: &http.Client{Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}
	now := time.Now()
	op := &Operator{Kube: kube, Namespace: "deck-system", Log: log.New(io.Discard, "", 0), Now: func() time.Time { return now },
		Cfg: Config{SpaceImage: "ghcr.io/example/deck-space:test", RuntimeClass: "gvisor", DeleteDelay: 24 * time.Hour,
			KeyguardURL: "http://keyguard.deck-keys.svc.cluster.local:8080", SquidURL: "http://squid.deck-egress.svc.cluster.local:3128",
			SSHGatewayURL: "http://ssh-gateway.deck-ssh.svc.cluster.local:8080",
			SpaceDNS:      "10.43.0.53", StorageClass: "local-path"},
		Verify: func(context.Context, string) (Verified, error) {
			var v Verified
			v.Action.Type, v.Action.Space, v.User, v.DeviceID = "space_delete", "u-zoe", "zoe", "d-test"
			return v, nil
		}}
	ctx := context.Background()
	const sp, ns = "/apis/deck.fugu/v1alpha1/namespaces/deck-system/spaces/zoe", "/api/v1/namespaces/deck-u-zoe"
	if _, err := kube.do(ctx, http.MethodPatch, sp, "application/merge-patch+json", map[string]any{"spec": map[string]any{
		"deleteRequestedAt": now.UTC().Format(time.RFC3339), "deleteSignature": "aGVhZA.Ym9keQ.c2ln"}}); err != nil {
		t.Fatalf("запрос удаления: %v", err)
	}
	if err := op.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	z, err := kube.Get(ctx, sp)
	if err != nil || str(z, "status", "phase") != "Deleting" || str(z, "status", "deleteAt") == "" || str(z, "status", "deleteVerified") != sigHash("aGVhZA.Ym9keQ.c2ln") {
		t.Fatalf("принятый запрос: %v %v", err, z["status"])
	}
	if _, err := kube.Get(ctx, ns); err != nil {
		t.Fatalf("до срока namespace на месте: %v", err)
	}
	now = now.Add(25 * time.Hour)
	deadline := time.Now().Add(90 * time.Second)
	for {
		if err := op.ReconcileAll(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := kube.Get(ctx, sp); err == ErrNotFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("пространство не удалено за 90 с")
		}
		time.Sleep(2 * time.Second)
	}
	if _, err := kube.Get(ctx, ns); err != ErrNotFound {
		t.Fatalf("Space удалён раньше namespace: %v", err)
	}
	if _, err := kube.Get(ctx, "/api/v1/namespaces/deck-u-anna"); err != nil {
		t.Fatalf("соседнее пространство задето: %v", err)
	}
	// Удалять можно только пространства: namespace платформы оператору не удалить.
	if err := kube.Delete(ctx, "/api/v1/namespaces/deck-keys"); err == nil {
		t.Fatal("оператор смог удалить namespace deck-keys")
	}
}
