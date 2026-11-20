package keyguard

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAccountDeletePurge(t *testing.T) {
	k := newRig(t)
	k.seed()
	c := &check{t: t}
	j := func(v any) []byte { b, _ := json.Marshal(v); return b }
	verify := func(tok string, sa SignedAction) int {
		st, _ := k.do("POST", "/v1/actions/verify", tok, j(sa), nil)
		return st
	}
	purge := func(tok, user string) (int, string) {
		return k.do("POST", "/v1/account/purge", tok, j(map[string]string{"user": user}), nil)
	}

	st, _ := purge("tok-random", "anna")
	c.ok("A1 без проверенной подписи стереть нельзя", st == 403, st)
	bad := k.mallory.sign(t, k, map[string]any{"type": "account_delete", "user": "anna"}, nil)
	c.ok("A2 чужой аккаунт подписью не удалить", verify("tok-random", bad) == 403)
	sa := k.anna.sign(t, k, map[string]any{"type": "account_delete", "user": "anna"}, nil)
	c.ok("A3 control-plane подпись удаления аккаунта не проверяет", verify("tok-cp", sa) == 403)
	c.ok("A4 оператор проверил подпись Анны", verify("tok-random", sa) == 200)
	st, _ = purge("tok-random", "anna")
	c.ok("A5 раньше суток — отказ", st == 403, st)
	st, _ = purge("tok-cp", "anna")
	c.ok("A6 стирает только оператор", st == 403, st)

	k.clock = k.clock.Add(24 * time.Hour)
	st, b := purge("tok-random", "anna")
	c.ok("A7 через сутки стёрто", st == 200 && strings.Contains(b, `"keys":2`) && strings.Contains(b, `"devices":1`), st, b)
	_, err := k.srv.Store.Get(nil, "anna", "sakana")
	d, _ := k.srv.Verifier.Devices.Get("dev-anna")
	c.ok("A8 ключей нет, устройство отозвано", err == ErrNoKey && d.Revoked, err)
	_, err = k.srv.Store.Get(nil, "bob", "sakana")
	c.ok("A9 ключи Боба на месте", err == nil, err)
	st, b = purge("tok-random", "anna")
	c.ok("A10 повтор — не ошибка", st == 200 && strings.Contains(b, "already"), st, b)
	st, _ = k.do("POST", "/llm/anthropic/v1/messages", "tok-anna", []byte(`{"model":"claude-x","max_tokens":10,"messages":[]}`), nil)
	c.ok("A11 пространство Анны больше не получает модель (ключа нет)", st != 200, st)

	// Отмена: Боб подписал, передумал в течение суток — стереть его нельзя и потом.
	sb := k.bob.sign(t, k, map[string]any{"type": "account_delete", "user": "bob"}, nil)
	c.ok("A12 подпись Боба проверена", verify("tok-random", sb) == 200)
	st, _ = k.do("POST", "/v1/account/cancel", "tok-cp", j(map[string]string{"user": "bob"}), nil)
	c.ok("A13 control-plane отменил удаление", st == 200, st)
	k.clock = k.clock.Add(48 * time.Hour)
	st, _ = purge("tok-random", "bob")
	c.ok("A14 после отмены стереть нельзя", st == 403, st)
	st, _ = k.do("POST", "/v1/account/cancel", "tok-cp", j(map[string]string{"user": "anna"}), nil)
	c.ok("A15 отменить уже стёртое нельзя", st == 409, st)

	// Неактивность: без подписи — только если keyguard сам не видел пользователя 29 дней.
	inactive := func(user string) int {
		st, _ := k.do("POST", "/v1/account/purge", "tok-random", j(map[string]string{"user": user, "reason": "inactive"}), nil)
		return st
	}
	k.srv.Store.Put(nil, "carol", "sakana", "sk-sak-CAROL-0123456789")
	c.ok("A16 сведений об активности нет — отказ, отсчёт начат", inactive("carol") == 403)
	k.clock = k.clock.Add(10 * 24 * time.Hour)
	c.ok("A17 через 10 дней — рано", inactive("carol") == 403)
	k.clock = k.clock.Add(20 * 24 * time.Hour)
	c.ok("A18 через 30 дней без активности — стёрто", inactive("carol") == 200)
	_, err = k.srv.Store.Get(nil, "carol", "sakana")
	c.ok("A19 ключ неактивного стёрт", err == ErrNoKey, err)
	// Боб подписывает действие — для keyguard он активен, «неактивность» его не сотрёт.
	k.clock = k.clock.Add(40 * 24 * time.Hour)
	verify("tok-random", k.bob.sign(t, k, map[string]any{"type": "space_delete", "space": "u-bob"}, nil))
	c.ok("A20 активного по неактивности не стереть", inactive("bob") == 403)
}
