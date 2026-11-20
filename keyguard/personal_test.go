package keyguard

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Личные ключи и расходы: удаление ключа, статус, месячный лимит.
func TestPersonalKeysAndLimit(t *testing.T) {
	k := newRig(t)
	k.seed()
	c := &check{t: t}
	j := func(v any) []byte { b, _ := json.Marshal(v); return b }
	msg := []byte(`{"model":"claude-x","max_tokens":1000,"messages":[{"role":"user","content":"hi"}]}`)
	status := func(user string) map[string]any {
		st, b := k.do("POST", "/v1/keys/status", "tok-cp", j(map[string]string{"user": user}), nil)
		var out map[string]any
		json.Unmarshal([]byte(b), &out)
		if st != 200 {
			t.Fatalf("status %d %s", st, b)
		}
		return out
	}

	s := status("anna")
	c.ok("K1 статус: заданы ключи Anthropic и Sakana, лимита нет", fmt.Sprint(s["providers"]) == "[anthropic sakana]" && s["limit_usd_month"] == nil, s)
	st, _ := k.do("POST", "/v1/keys/status", "tok-anna", j(map[string]string{"user": "anna"}), nil)
	c.ok("K2 статус — только control-plane", st == 403, st)
	st, b0 := k.do("GET", "/v1/keys/mine", "tok-anna", nil, nil)
	c.ok("K2a своё пространство видит только имена провайдеров моделей со своими ключами", st == 200 && strings.TrimSpace(b0) == `{"providers":["anthropic","sakana"]}`, st, b0)
	st, _ = k.do("GET", "/v1/keys/mine", "tok-cp", nil, nil)
	c.ok("K2b не пространству — отказ", st == 403, st)

	del := k.anna.sign(t, k, map[string]any{"type": "key_delete", "provider": "sakana"}, nil)
	st, _ = k.do("POST", "/v1/keys/delete", "tok-anna", j(del), nil)
	c.ok("K3 удаление — только через control-plane", st == 403, st)
	st, b := k.do("POST", "/v1/keys/delete", "tok-cp", j(del), nil)
	c.ok("K4 ключ Sakana удалён по подписи", st == 200, st, b)
	_, err := k.srv.Store.Get(nil, "anna", "sakana")
	c.ok("K5 ключа больше нет в хранилище", err == ErrNoKey, err)
	st, _ = k.do("POST", "/v1/keys/delete", "tok-cp", j(del), nil)
	c.ok("K6 повтор той же подписи отклонён", st == 403, st)
	_, err = k.srv.Store.Get(nil, "bob", "sakana")
	c.ok("K7 ключ Боба не тронут (чей ключ — по устройству)", err == nil, err)
	put := k.anna.sign(t, k, map[string]any{"type": "key_put", "provider": "sakana", "key_hint": "abcd", "ct_sha256": strings.Repeat("0", 64)}, nil)
	st, _ = k.do("POST", "/v1/keys/delete", "tok-cp", j(put), nil)
	c.ok("K8 подпись другого типа (key_put) удалением не считается", st == 403, st)

	// Лимит месяца: $0.02, один запрос стоит 0.0105 — второй уже не помещается в резерв.
	lim := k.anna.sign(t, k, map[string]any{"type": "spend_limit", "limit_usd_month": json.Number("0.02")}, nil)
	st, b = k.do("POST", "/v1/limits", "tok-cp", j(lim), nil)
	c.ok("L1 лимит $0.02 в месяц поставлен", st == 200 && strings.Contains(b, `"limit_usd_month":0.02`), st, b)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", msg, nil)
	c.ok("L2 первый запрос проходит", st == 200, st)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", msg, nil)
	c.ok("L3 второй — сверх лимита месяца", st == 402 || st == 429 || st == 403, st)
	s = status("anna")
	c.ok("L4 статус: потрачено за месяц и лимит", s["limit_usd_month"] == 0.02 && s["spent_usd_month"].(float64) > 0.01, s)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-bob", msg, nil)
	c.ok("L5 лимит Анны не касается Боба", st == 200, st)

	k.clock = k.clock.Add(31 * 24 * time.Hour) // новый месяц — расход с нуля, лимит тот же
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", msg, nil)
	c.ok("L6 в новом месяце запрос снова проходит", st == 200, st)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", msg, nil)
	c.ok("L7 и лимит в новом месяце действует", st != 200, st)

	off := k.anna.sign(t, k, map[string]any{"type": "spend_limit", "limit_usd_month": nil}, nil)
	st, b = k.do("POST", "/v1/limits", "tok-cp", j(off), nil)
	c.ok("L8 лимит снят", st == 200 && strings.Contains(b, `"limit_usd_month":null`), st, b)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", msg, nil)
	c.ok("L9 без лимита запрос проходит", st == 200, st)
	bad := k.anna.sign(t, k, map[string]any{"type": "spend_limit", "limit_usd_month": json.Number("0.001")}, nil)
	st, _ = k.do("POST", "/v1/limits", "tok-cp", j(bad), nil)
	c.ok("L10 сумма с тремя знаками отклонена схемой", st == 403, st)
}
