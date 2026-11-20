package keyguard

// Схема подписанных действий — зеркало fugu-deck-app/mobile/src/core/actions.ts (единственный источник — приложение).
// Приложение показывает человеку текст, построенный из полей действия; keyguard обязан отклонить всё, чего на экране
// быть не могло: неизвестный тип, лишнее или недостающее поле, невидимые и bidi-символы в строках, поле space у
// действия вне пространства. Расхождение двух реализаций ловят общие векторы (testdata/action-vectors.json):
// каждый «valid» обязан пройти здесь, каждый «invalid» — быть отклонён и здесь, и в приложении.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

type fieldCheck func(v any) bool

type actionSchema struct {
	inSpace  bool // действие в пространстве: space в конверте обязателен; иначе поля space нет вовсе
	fields   map[string]fieldCheck
	optional map[string]fieldCheck       // необязательные поля: проверяются, только если есть (совместимость со старым приложением)
	post     func(a map[string]any) bool // проверки между полями
}

// C0/C1, zero-width, bidi-override/isolate, BOM, разделители строк — как HIDDEN в actions.ts.
var hiddenRe = regexp.MustCompile(`[\x{0000}-\x{001f}\x{007f}-\x{009f}\x{00ad}\x{061c}\x{115f}\x{1160}\x{180e}\x{200b}-\x{200f}\x{2028}-\x{202e}\x{2060}-\x{206f}\x{feff}\x{fff9}-\x{fffb}]`)

func re(p string) *regexp.Regexp { return regexp.MustCompile(p) }

var (
	idRe       = re(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	deviceIDRe = re(`^[A-Za-z0-9_-]{8,64}$`)
	jktRe      = re(`^[A-Za-z0-9_-]{43}$`)
	spaceRe    = re(`^[A-Za-z0-9][A-Za-z0-9:._-]*$`)
	nonceRe    = re(`^[A-Za-z0-9_-]{16,64}$`)
	dateRe     = re(`^\d{4}-\d{2}-\d{2}$`)
	moneyRe    = re(`^\d+(\.\d{1,2})?$`)
	wholeRe    = re(`^-?\d+$`)
	mcpIDRe    = re(`^[a-z][a-z0-9-]{1,30}$`)
	domainRe   = re(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	hostRe     = re(`^([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$|^\d{1,3}(\.\d{1,3}){3}$|^\[[0-9A-Fa-f:]+\]$`)
)

// str — непустая строка не длиннее max (в единицах UTF-16, как length в JavaScript), без невидимых символов и
// пробелов по краям; rx — формат.
func str(max int, rx *regexp.Regexp) fieldCheck {
	return func(v any) bool {
		x, ok := v.(string)
		if !ok || x == "" || len(utf16.Encode([]rune(x))) > max || hiddenRe.MatchString(x) || x != jsTrim(x) {
			return false
		}
		return rx == nil || rx.MatchString(x)
	}
}

// jsTrim — String.prototype.trim: пробельные символы ECMAScript (шире, чем strings.TrimSpace).
func jsTrim(x string) string {
	return strings.Trim(x, "\t\n\v\f\r                  　\ufeff")
}

var (
	idF       = str(63, idRe)
	deviceIDF = str(64, deviceIDRe)
)

func dateF(v any) bool {
	if !str(10, dateRe)(v) {
		return false
	}
	_, err := time.Parse("2006-01-02", v.(string))
	return err == nil
}

func intF(min, max int64) fieldCheck {
	return func(v any) bool {
		n, ok := v.(json.Number)
		if !ok || !wholeRe.MatchString(string(n)) {
			return false
		}
		x, err := strconv.ParseInt(string(n), 10, 64)
		return err == nil && x >= min && x <= max
	}
}

// moneyF — сумма больше 0 и не больше 100 000, не более двух знаков после запятой.
func moneyF(v any) bool {
	n, ok := v.(json.Number)
	if !ok || !moneyRe.MatchString(string(n)) {
		return false
	}
	x, err := strconv.ParseFloat(string(n), 64)
	return err == nil && x > 0 && x <= 100000
}

func boolF(v any) bool { _, ok := v.(bool); return ok }

func oneOf(vals ...string) fieldCheck {
	return func(v any) bool { x, ok := v.(string); return ok && contains(vals, x) }
}

func nullable(c fieldCheck) fieldCheck { return func(v any) bool { return v == nil || c(v) } }

// list — от min до max элементов без повторов.
func list(c fieldCheck, min, max int) fieldCheck {
	return func(v any) bool {
		xs, ok := v.([]any)
		if !ok || len(xs) < min || len(xs) > max {
			return false
		}
		seen := map[any]bool{}
		for _, x := range xs {
			if !c(x) || seen[x] {
				return false
			}
			seen[x] = true
		}
		return true
	}
}

var allProviders = []string{"anthropic", "sakana", "deepseek", "openai", "xai", "google", "kimi", "moonshot", "qwen", "mistral", "minimax", "zai", "github", "gitlab", "google_drive"}

var actionSchemas = map[string]actionSchema{
	"key_put": {fields: map[string]fieldCheck{
		"provider": oneOf(allProviders...), "key_hint": str(4, re(`^[A-Za-z0-9_-]{4}$`)), "ct_sha256": str(64, re(`^[0-9a-f]{64}$`))}},
	"key_delete": {fields: map[string]fieldCheck{"provider": oneOf(allProviders...)}},
	// MCP-сервер владельца (mcp.go): адрес и, если нужен, токен — HPKE, как ключ API; token_hint — его последние 4 знака.
	"mcp_put": {fields: map[string]fieldCheck{
		"id": str(31, mcpIDRe), "name": str(60, nil), "url": str(300, re(`^https://[!-~]+$`)),
		"token_hint": nullable(str(4, re(`^[A-Za-z0-9_-]{4}$`))), "ct_sha256": nullable(str(64, re(`^[0-9a-f]{64}$`)))},
		post: func(a map[string]any) bool { return (a["token_hint"] == nil) == (a["ct_sha256"] == nil) }},
	"mcp_delete": {fields: map[string]fieldCheck{"id": str(31, mcpIDRe)}},
	// Домены, с которых агент личного пространства читает страницы через keyguard (egress.go): весь список целиком.
	"egress_set": {fields: map[string]fieldCheck{"domains": list(str(253, domainRe), 0, 50)}},
	// Лимит личных расходов на модели в месяц (своим ключом в личном пространстве); null — без лимита.
	"spend_limit": {fields: map[string]fieldCheck{"limit_usd_month": nullable(moneyF)}},
	"grant": {inSpace: true, fields: map[string]fieldCheck{
		"chat": idF, "provider": oneOf(allProviders...), "model": str(80, re(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)),
		"limit_usd": moneyF, "limit_tokens": nullable(intF(1, 1_000_000_000)), "until": dateF, "key_until": dateF,
		"per_member_usd_day": nullable(moneyF), "members": list(idF, 1, 50), "proposal": idF},
		post: func(a map[string]any) bool {
			git := s(a, "provider") == "github" || s(a, "provider") == "gitlab"
			return s(a, "key_until") <= s(a, "until") && git == (s(a, "model") == "git")
		}},
	"grant_revoke": {inSpace: true, fields: map[string]fieldCheck{"chat": idF, "proposal": idF}},
	"server_add": {inSpace: true, fields: map[string]fieldCheck{
		"server": idF, "host": str(253, hostRe), "port": intF(1, 65535), "user": str(32, re(`^[a-z_][a-z0-9_-]{0,31}$`)),
		"host_key": str(50, re(`^SHA256:[A-Za-z0-9+/]{43}$`))}},
	"agent_rights": {inSpace: true, fields: map[string]fieldCheck{
		"agent": idF, "servers": list(idF, 0, 50), "read_without_confirm": boolF, "limit_usd_month": nullable(moneyF)},
		// write_without_confirm — изменения (write) на серверах агента без подписи каждой команды, до срока
		// write_auto_until (unix-секунды). Danger — никогда. Поля необязательные: старое приложение их не шлёт.
		optional: map[string]fieldCheck{"write_without_confirm": boolF, "write_auto_until": nullable(intF(0, 4102444800))},
		post: func(a map[string]any) bool {
			w, _ := a["write_without_confirm"].(bool)
			return !w || intF(0, 4102444800)(a["write_auto_until"]) // включил авто-write — обязан дать срок
		}},
	"ssh_write": {inSpace: true, fields: map[string]fieldCheck{"agent": idF, "server": idF, "command": str(2000, nil)}},
	"ssh_danger": {inSpace: true, fields: map[string]fieldCheck{"agent": idF, "server": idF, "command": str(2000, nil), "typed_server": idF},
		post: func(a map[string]any) bool { return s(a, "typed_server") == s(a, "server") }},
	"role_change":    {inSpace: true, fields: map[string]fieldCheck{"member": idF, "role": oneOf("reader", "editor", "owner", "none")}}, // none — исключить участника
	"device_enroll":  {fields: map[string]fieldCheck{"session_jkt": str(43, jktRe), "confirm_jkt": str(43, jktRe), "name": str(80, nil)}},
	"device_approve": {fields: map[string]fieldCheck{"user": idF, "target": deviceIDF, "name": str(80, nil)}},
	"device_revoke":  {fields: map[string]fieldCheck{"user": idF, "target": deviceIDF}},
	"pair_approve": {fields: map[string]fieldCheck{
		"pairing": str(43, jktRe), "user": idF, "target": deviceIDF, "name": str(80, nil),
		"code": str(8, re(`^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$`)), "session_jkt": str(43, jktRe)}},
	// Приглашение на ник user: себе (ещё одно устройство) — любой пользователь, другому — только администратор.
	"invite_create":  {fields: map[string]fieldCheck{"user": idF}},
	"account_delete": {fields: map[string]fieldCheck{"user": idF}},
	"space_delete":   {inSpace: true, fields: map[string]fieldCheck{}},
	"tool_approve": {inSpace: true, fields: map[string]fieldCheck{
		"approval": str(64, re(`^[A-Za-z0-9_-]{1,64}$`)), "tool": str(80, re(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)),
		"args_sha256": str(43, jktRe)}}, // SHA-256 в base64url — как считает агент (devices.args_hash)
}

// ValidateAction проверяет конверт действия целиком: тип, точный набор полей, значения, space, device_id, nonce, ts.
func ValidateAction(a map[string]any) error {
	typ, _ := a["type"].(string)
	sc, ok := actionSchemas[typ]
	if !ok {
		return fmt.Errorf("%w: неизвестный тип действия %q", ErrBadAction, typ)
	}
	envelope := map[string]fieldCheck{"device_id": deviceIDF, "nonce": str(64, nonceRe), "ts": intF(0, 4102444800)}
	if sc.inSpace {
		envelope["space"] = str(80, spaceRe)
	}
	for k := range a {
		_, f := sc.fields[k]
		_, o := sc.optional[k]
		if !f && !o && envelope[k] == nil && k != "type" {
			return fmt.Errorf("%w: лишнее поле %q", ErrBadAction, k)
		}
	}
	for _, set := range []map[string]fieldCheck{sc.fields, envelope} {
		for k, check := range set {
			v, present := a[k]
			if !present {
				return fmt.Errorf("%w: нет поля %q", ErrBadAction, k)
			}
			if !check(v) {
				return fmt.Errorf("%w: поле %q", ErrBadAction, k)
			}
		}
	}
	for k, check := range sc.optional { // необязательные: проверяем, только если присутствуют
		if v, present := a[k]; present && !check(v) {
			return fmt.Errorf("%w: поле %q", ErrBadAction, k)
		}
	}
	if sc.post != nil && !sc.post(a) {
		return fmt.Errorf("%w: поля не согласованы между собой", ErrBadAction)
	}
	return nil
}
