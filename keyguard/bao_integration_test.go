package keyguard

// Живой OpenBao 2.7 (dev) + политика keyguard.hcl из инфраструктурного репозитория.
// Пропускается, если нет бинарника: BAO_BIN (по умолчанию /tmp/bin/bao), KEYGUARD_POLICY (путь к keyguard.hcl).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func TestIntegration_OpenBao(t *testing.T) {
	bin := envOr("BAO_BIN", "/tmp/bin/bao")
	pol := envOr("KEYGUARD_POLICY", "../fugu-deck-infra/terraform/openbao/policies/keyguard.hcl")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("нет бинарника OpenBao")
	}
	policy, err := os.ReadFile(pol)
	if err != nil {
		t.Skip("нет keyguard.hcl")
	}
	const addr, root = "http://127.0.0.1:8355", "root-kg"
	cmd := exec.Command(bin, "server", "-dev", "-dev-root-token-id="+root, "-dev-listen-address=127.0.0.1:8355")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	call := func(tok, method, path string, body any) (int, map[string]any) {
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, addr+"/v1/"+path, rd)
		req.Header.Set("X-Vault-Token", tok)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil
		}
		defer r.Body.Close()
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		return r.StatusCode, m
	}
	for i := 0; i < 100; i++ {
		if st, _ := call(root, "GET", "sys/health", nil); st == 200 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// как terraform/openbao/main.tf: KV v2 deck, cas_required, max_versions 20; platform — для проверки границ
	call(root, "POST", "sys/mounts/deck", map[string]any{"type": "kv", "options": map[string]any{"version": "2"}})
	call(root, "POST", "deck/config", map[string]any{"cas_required": true, "max_versions": 20})
	call(root, "POST", "sys/mounts/platform", map[string]any{"type": "kv", "options": map[string]any{"version": "2"}})
	call(root, "PUT", "sys/policies/acl/keyguard", map[string]any{"policy": string(policy)})
	_, tj := call(root, "POST", "auth/token/create", map[string]any{"policies": []string{"keyguard"}, "no_parent": true, "ttl": "10m"})
	tok := tj["auth"].(map[string]any)["client_token"].(string)

	c := &check{t: t}
	b := &BaoStore{Addr: addr, Mount: "deck", HTTP: http.DefaultClient, Token: func(context.Context) (string, error) { return tok, nil }}
	ctx := context.Background()

	err = b.Put(ctx, "anna", "anthropic", "sk-ant-ANNA-v1-000000")
	c.ok("B1 keyguard пишет ключ при cas_required (первая версия, cas=0)", err == nil, err)
	err = b.Put(ctx, "anna", "anthropic", "sk-ant-ANNA-v2-000000")
	got, _ := b.Get(ctx, "anna", "anthropic")
	c.ok("B2 замена ключа (cas = текущая версия) и чтение новой", err == nil && got == "sk-ant-ANNA-v2-000000", err, got)
	_, md := call(root, "GET", "deck/metadata/keys/anna/anthropic", nil)
	cv := md["data"].(map[string]any)["current_version"].(float64)
	c.ok("B3 старая версия сохранена (откат испорченного ключа)", cv == 2, cv)
	_, err = b.Get(ctx, "bob", "anthropic")
	c.ok("B4 отсутствующий ключ → ErrNoKey", err == ErrNoKey, err)

	for _, u := range []string{"../../sys", "anna/../bob", "anna%2f..", "ANNA", ""} {
		err := b.Put(ctx, u, "anthropic", "sk-x-00000000")
		c.ok("B5 имя "+u+" не попадает в путь OpenBao", err != nil && strings.Contains(err.Error(), "недопустимое"), err)
	}

	// границы политики keyguard: только deck/*, без platform и без управления
	st, _ := call(tok, "GET", "platform/data/s3", nil)
	c.ok("B6 токен keyguard не читает platform/*", st == 403, st)
	st, _ = call(tok, "PUT", "sys/policies/acl/keyguard", map[string]any{"policy": `path "*" {capabilities=["sudo","read"]}`})
	c.ok("B7 токен keyguard не может расширить свою политику", st == 403, st)
	st, _ = call(tok, "POST", "auth/token/create", map[string]any{"policies": []string{"root"}})
	c.ok("B8 токен keyguard не выпускает токен с чужой политикой", st == 403, st)

	// полный путь: ввод ключа через HPKE в настоящий OpenBao, затем прокси подставляет его провайдеру
	k := newRig(t)
	k.srv.Store = b
	r, _ := k.sealedKeyPut(k.anna, "sakana", "sk-sak-ANNA-0123456789", nil)
	st, _ = k.do("POST", "/v1/keys", "tok-cp", j(r), nil)
	stored, _ := b.Get(ctx, "anna", "sakana")
	c.ok("B9 ключ из телефона (HPKE) лёг в настоящий OpenBao", st == 200 && stored == "sk-sak-ANNA-0123456789", st)
	st, _ = k.do("POST", "/llm/sakana/v1/chat/completions", "tok-anna", []byte(`{"model":"fugu-max-v1.0","max_tokens":10,"messages":[]}`), nil)
	up, _ := k.sak.last()
	c.ok("B10 прокси взял ключ из OpenBao и подставил провайдеру", st == 200 && up.Header.Get("Authorization") == "Bearer sk-sak-ANNA-0123456789", st)
	// удаление аккаунта: политика позволяет keyguard стереть ключ со всеми версиями — и только по полному пути
	st, _ = call(tok, "DELETE", "deck/metadata/keys/anna/anthropic", nil)
	_, err = b.Get(ctx, "anna", "anthropic")
	c.ok("B11 keyguard может удалить ключ со всеми версиями (удаление аккаунта)", (st == 204 || st == 200) && err == ErrNoKey, st, err)
	st, _ = call(tok, "DELETE", "deck/metadata/keyguard/hpke", nil)
	c.ok("B12 но не свой ключ HPKE", st == 403, st)
	t.Logf("OpenBao: %d/%d", c.n, c.n+c.f)
}
