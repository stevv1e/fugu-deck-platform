package keyguard

// Атаки на перезапуск keyguard (блокер №1 из README): всё, что раньше жило только в памяти, обязано пережить
// перезапуск — иначе подпись можно повторить, лимит спонсора обнуляется, а отозванное устройство «воскресает».
// Один и тот же набор проверок идёт на хранилище в памяти (MemState) и на настоящем Postgres (pg_integration_test.go).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// restart — новый процесс keyguard: то же окружение (провайдеры, OpenBao, ключ HPKE), пустая память, состояние из p.
func (k *rig) restart(p Persister) {
	k.t.Helper()
	old := k.srv
	k.ts.Close()
	k.srv = &Server{Providers: old.Providers, Store: old.Store, Auth: old.Auth, HPKEKey: old.HPKEKey, Upstream: old.Upstream,
		Log: old.Log, Now: old.Now, MaxBody: old.MaxBody, ControlPlane: old.ControlPlane, ActionVerifiers: old.ActionVerifiers,
		Enroll: old.Enroll, Certs: old.Certs,
		Verifier: &Verifier{Devices: NewDevices(), Nonces: NewNonces(), Now: old.Verifier.Now}, Ledger: NewLedger(), Grants: NewGrants()}
	if err := k.srv.Restore(context.Background(), p); err != nil {
		k.t.Fatalf("восстановление состояния: %v", err)
	}
	k.ts = httptest.NewServer(k.srv.Handler())
	k.t.Cleanup(k.ts.Close)
}

// restartSuite: open() возвращает хранилище, смотрящее на ТЕ ЖЕ данные (новое подключение — как у нового процесса);
// breakStore/fixStore ломают и чинят хранилище (fixStore == nil — починка не проверяется).
func restartSuite(t *testing.T, open func() Persister, breakStore, fixStore func()) {
	k := newRig(t)
	k.seed()
	c := &check{t: t}
	k.restart(open())
	for _, p := range []*phone{k.anna, k.bob, k.mallory} { // устройства стенда — теперь через хранилище
		if err := k.srv.Verifier.Devices.Add(p.dev); err != nil {
			t.Fatal(err)
		}
	}
	put := func(r keyPutReq) (int, string) { return k.do("POST", "/v1/keys", "tok-cp", j(r), nil) }
	llm := []byte(`{"model":"claude-x","max_tokens":1000,"messages":[]}`)
	reserve := (float64(len(llm))*3 + 1000*15) / 1e6
	const fact = (1000*3 + 500*15) / 1e6 // мок провайдера: 1000 входных и 500 выходных токенов

	// ---- повтор подписи после перезапуска ----
	r, _ := k.sealedKeyPut(k.anna, "anthropic", "sk-ant-ANNA-0123456789", nil)
	st, _ := put(r)
	c.ok("R1 ввод ключа принят", st == 200, st)
	k.restart(open())
	st, body := put(r)
	c.ok("R2 тот же подписанный запрос после перезапуска — отказ (nonce в хранилище)", st == 403 && strings.Contains(body, "nonce"), st, body)

	// ---- расходы и лимиты ----
	if err := k.srv.Ledger.SetLimit("user:anna", fact+reserve*1.5); err != nil { // хватает на два запроса, на третий — нет
		t.Fatal(err)
	}
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", llm, nil)
	spent := k.srv.Ledger.Spent("user:anna")
	c.ok("R3 запрос к модели прошёл, расход записан по факту", st == 200 && abs(spent-fact) < 1e-9, st, spent)
	k.restart(open())
	c.ok("R4 после перезапуска расход НЕ обнулился", abs(k.srv.Ledger.Spent("user:anna")-fact) < 1e-9, k.srv.Ledger.Spent("user:anna"))
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", llm, nil)
	st2, _ := k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", llm, nil)
	c.ok("R5 лимит пережил перезапуск: второй запрос проходит, третий — 402", st == 200 && st2 == 402, st, st2)

	// ---- процесс упал посреди запроса: резерв остаётся расходом ----
	if _, err := k.srv.Ledger.Reserve([]string{"user:bob"}, 0.25); err != nil {
		t.Fatal(err)
	}
	k.restart(open()) // Settle не было
	c.ok("R6 падение посреди запроса: в учёте остался резерв, а не ноль", abs(k.srv.Ledger.Spent("user:bob")-0.25) < 1e-9, k.srv.Ledger.Spent("user:bob"))

	// ---- разрешения спонсоров ----
	until := k.now().Add(24 * time.Hour).Format("2006-01-02")
	grant := map[string]any{"type": "grant", "space": "t-shop", "chat": "c-1", "provider": "sakana", "model": "fugu-max-v1.0",
		"limit_usd": jnum("1"), "limit_tokens": nil, "per_member_usd_day": jnum("0.5"), "until": until, "key_until": until,
		"members": []any{"anna"}, "proposal": "p-1"}
	st, body = k.do("POST", "/v1/grants", "tok-cp", j(k.bob.sign(t, k, grant, nil)), nil)
	gid := between(body, `"grant_id":"`, `"`)
	st2, _ = k.do("POST", "/v1/grants/activate", "tok-shop", j(map[string]string{"grant_id": gid}), nil)
	c.ok("R7 разрешение создано и активировано", st == 200 && st2 == 200 && gid != "", st, st2, body)
	shop := func() (int, string) {
		return k.do("POST", "/llm/sakana/v1/chat/completions", "tok-shop", []byte(`{"model":"fugu-max-v1.0","max_tokens":1000,"messages":[]}`),
			map[string]string{"X-Deck-Chat": "c-1", "X-Deck-Member": "anna"})
	}
	k.restart(open())
	st, body = shop()
	g, _ := k.srv.Grants.Get(gid)
	c.ok("R8 после перезапуска разрешение действует, спонсор и участники те же", st == 200 && g != nil && g.Active && g.Sponsor == "bob" && len(g.Members) == 1, st, body)
	dayKey := "grant:" + gid + ":anna:" + k.now().UTC().Format("2006-01-02")
	sg, sd := k.srv.Ledger.Spent("grant:"+gid), k.srv.Ledger.Spent(dayKey)
	k.restart(open())
	c.ok("R9 расход по разрешению и дневной расход участника пережили перезапуск",
		sg > 0 && abs(k.srv.Ledger.Spent("grant:"+gid)-sg) < 1e-9 && abs(k.srv.Ledger.Spent(dayKey)-sd) < 1e-9, sg, sd)
	st, _ = k.do("POST", "/v1/grants/revoke", "tok-cp", j(k.bob.sign(t, k, map[string]any{"type": "grant_revoke", "space": "t-shop", "chat": "c-1", "proposal": "p-1"}, nil)), nil)
	k.restart(open())
	st2, _ = shop()
	c.ok("R10 отозванное разрешение после перезапуска остаётся отозванным", st == 200 && st2 == 403, st, st2)

	// ---- устройства ----
	if err := k.srv.Verifier.Devices.Add(&Device{ID: "dev-new", User: "anna", SessionPub: k.mallory.dev.SessionPub, ConfirmPub: k.mallory.dev.ConfirmPub,
		Pending: true, Name: "новый телефон", KeyStorage: "tee", Attested: "android-key/tee", CSR: "csr"}); err != nil {
		t.Fatal(err)
	}
	st, _ = k.do("POST", "/v1/devices/revoke", "tok-cp", j(k.anna.sign(t, k, map[string]any{"type": "device_revoke", "user": "anna", "target": "dev-anna"}, nil)), nil)
	c.ok("R11 Анна отозвала своё устройство", st == 200, st)
	k.restart(open())
	_, _, err := k.srv.Verifier.Verify(k.anna.sign(t, k, map[string]any{"type": "account_delete", "user": "anna"}, nil), "account_delete")
	c.ok("R12 отозванное устройство после перезапуска остаётся отозванным", errors.Is(err, ErrRevoked), err)
	nd, ok := k.srv.Verifier.Devices.Get("dev-new")
	c.ok("R13 неподтверждённое устройство после перезапуска не стало подтверждённым; поля целы",
		ok && nd.Pending && !nd.Revoked && nd.User == "anna" && nd.Name == "новый телефон" && nd.KeyStorage == "tee" && nd.Attested == "android-key/tee" && nd.CSR == "csr" &&
			nd.ConfirmPub.Equal(k.mallory.dev.ConfirmPub) && nd.SessionPub.Equal(k.mallory.dev.SessionPub), nd)
	_, _, err = k.srv.Verifier.Verify(k.bob.sign(t, k, map[string]any{"type": "account_delete", "user": "anna"}, nil), "account_delete")
	c.ok("R14 остальные устройства после перезапуска работают", err == nil, err)

	// ---- хранилище недоступно: ничего не принимается «в долг» ----
	n0 := k.anth.count() + k.sak.count()
	breakStore()
	r, _ = k.sealedKeyPut(k.bob, "anthropic", "sk-ant-BOB-0123456789", nil)
	st, _ = put(r)
	c.ok("R15 хранилище недоступно: подписанное действие отклонено (nonce не записать)", st == 403, st)
	st, _ = k.do("POST", "/llm/sakana/v1/chat/completions", "tok-bob", []byte(`{"model":"fugu-max-v1.0","max_tokens":1000,"messages":[]}`), nil)
	c.ok("R16 хранилище недоступно: запрос к модели — 503, к провайдеру не ушёл (расход не записать)",
		st == 503 && k.anth.count()+k.sak.count() == n0, st, k.anth.count()+k.sak.count()-n0)
	c.ok("R17 хранилище недоступно: лимит не меняется", k.srv.Ledger.SetLimit("user:bob", 100) != nil)
	c.ok("R18 хранилище недоступно: устройство не добавляется", k.srv.Verifier.Devices.Add(&Device{ID: "dev-x", User: "bob",
		SessionPub: k.bob.dev.SessionPub, ConfirmPub: k.bob.dev.ConfirmPub}) != nil && func() bool { _, ok := k.srv.Verifier.Devices.Get("dev-x"); return !ok }())
	c.ok("R19 хранилище недоступно: отзыв устройства действует сразу, хотя и возвращает ошибку",
		k.srv.Verifier.Devices.Revoke("dev-bob-1") != nil && func() bool { d, _ := k.srv.Verifier.Devices.Get("dev-bob-1"); return d.Revoked }())
	c.ok("R20 в журнале есть причина отказа", strings.Contains(k.logs.String(), "event=state.error"))
	if fixStore != nil {
		fixStore()
		r, _ = k.sealedKeyPut(k.mallory, "anthropic", "sk-ant-BOB-0123456789", nil)
		st, _ = put(r)
		c.ok("R21 хранилище вернулось: работа продолжается", st == 200, st)
	}
	t.Logf("перезапуск: %d/%d", c.n, c.n+c.f)
}

func jnum(s string) any { return json.Number(s) }

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	if j := strings.Index(s, b); j >= 0 {
		return s[:j]
	}
	return ""
}

func TestAttack_Restart(t *testing.T) {
	m := NewMemState()
	restartSuite(t, func() Persister { return m },
		func() { m.Fail = fmt.Errorf("база недоступна") }, func() { m.Fail = nil })
}

// Аварийный отзыв из конфигурации: единственный администратор потерял устройство — после отзыва его следующее
// устройство снова считается первым (AnyActive ложно), а отозванное больше ничего не подпишет.
func TestRevokeListed(t *testing.T) {
	d := NewDevices()
	d.Add(&Device{ID: "d-lost", User: "admin"})
	d.Add(&Device{ID: "d-pending", User: "bob", Pending: true})
	if !d.AnyActive() {
		t.Fatal("активное устройство не учтено")
	}
	revoked, unknown, err := d.RevokeListed([]string{" d-lost ", "d-none", ""})
	if err != nil || len(revoked) != 1 || revoked[0] != "d-lost" || len(unknown) != 1 || unknown[0] != "d-none" {
		t.Fatalf("revoked=%v unknown=%v err=%v", revoked, unknown, err)
	}
	if x, _ := d.Get("d-lost"); !x.Revoked {
		t.Fatal("устройство не отозвано")
	}
	if d.AnyActive() {
		t.Fatal("после отзыва единственного устройства AnyActive истинно")
	}
	// повторный запуск с тем же списком ничего не делает
	if revoked, _, _ := d.RevokeListed([]string{"d-lost"}); len(revoked) != 0 {
		t.Fatalf("повторный отзыв: %v", revoked)
	}
	if x, _ := d.Get("d-pending"); x.Revoked {
		t.Fatal("отозвано устройство не из списка")
	}
}
