package keyguard

// Строгий JSON. Подписывается и проверяется ровно одна, каноничная форма: ключи по алфавиту, без пробелов,
// числа — целые или с одним-двумя знаками после запятой без хвостового нуля и без экспоненты (ровно так их пишет
// JSON.stringify приложения: 20, 12.5, 0.25). Та же форма — в modules/deck-security/src/canonical.ts;
// общие векторы — testdata/action-vectors.json. Дубликаты ключей отклоняются: иначе приложение показало бы человеку
// одно значение ("limit_usd":5), а сервер исполнил бы другое ("limit_usd":500) — разные парсеры берут разный дубликат.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	ErrDuplicateKey = errors.New("json: дубликат ключа")
	ErrNotCanonical = errors.New("json: не каноничная форма")
	ErrBadNumber    = errors.New("json: число не в каноничной форме (целое или до двух знаков после запятой)")
	ErrTrailingData = errors.New("json: данные после объекта")
	intRe           = regexp.MustCompile(`^(0|-?[1-9][0-9]{0,15})(\.([0-9][1-9]|[1-9]))?$|^-?0\.([0-9][1-9]|[1-9])$`)
)

// ParseStrict разбирает JSON-объект: отклоняет дубликаты ключей (на любой глубине) и данные после объекта.
// allowFloats=false — каноничные числа (для подписываемых действий); true — любые (тела запросов к провайдерам).
func ParseStrict(b []byte, allowFloats bool) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := parseValue(d, allowFloats, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrTrailingData
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("json: ожидался объект")
	}
	return m, nil
}

func parseValue(d *json.Decoder, allowFloats bool, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("json: слишком глубоко")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			m := map[string]any{}
			for d.More() {
				kt, err := d.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, k)
				}
				v, err := parseValue(d, allowFloats, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			_, err := d.Token() // '}'
			return m, err
		case '[':
			var a []any
			for d.More() {
				v, err := parseValue(d, allowFloats, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := d.Token() // ']'
			if a == nil {
				a = []any{}
			}
			return a, err
		}
	case json.Number:
		if !allowFloats && !intRe.MatchString(string(x)) {
			return nil, ErrBadNumber
		}
		return x, nil
	}
	return t, nil // string, bool, nil
}

// Canonical — каноничная сериализация (ключи по алфавиту, без пробелов).
func Canonical(v any) []byte {
	var b strings.Builder
	writeCanon(&b, v)
	return []byte(b.String())
}

func writeCanon(b *strings.Builder, v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSString(b, k)
			b.WriteByte(':')
			writeCanon(b, x[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanon(b, e)
		}
		b.WriteByte(']')
	case json.Number:
		b.WriteString(string(x))
	case string:
		writeJSString(b, x)
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case nil:
		b.WriteString("null")
	case float64: // только целые (как String(n) в JS для |n| < 1e21); дробные в подписываемых действиях отклоняет ParseStrict
		if x == math.Trunc(x) && math.Abs(x) < 1e21 {
			b.WriteString(strconv.FormatFloat(x, 'f', -1, 64))
		} else {
			b.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
		}
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	default:
		b.WriteString("null") // неизвестный тип не может дать валидную подпись — без паники
	}
}

// ParseCanonical — разбор подписываемого действия: строгий, только целые, и байты ОБЯЗАНЫ быть каноничными.
// Подпись проверяется над этими же байтами — одна строка, один смысл.
func ParseCanonical(b []byte) (map[string]any, error) {
	m, err := ParseStrict(b, false)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(Canonical(m), b) {
		return nil, ErrNotCanonical
	}
	return m, nil
}

// writeJSString — строка ровно как JSON.stringify в JavaScript (canonical.ts приложения) и Python ensure_ascii=False:
// экранируются только " \ и управляющие < 0x20 (короткие формы \b \f \n \r \t, остальные \u00xx строчными).
// Go json.Marshal дополнительно экранирует <, >, & и U+2028/U+2029 — подписи на таких строках не сходились бы.
func writeJSString(b *strings.Builder, x string) {
	b.WriteByte('"')
	for _, r := range x {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
