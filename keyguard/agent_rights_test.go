package keyguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func parseNum(b []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber() // числа как json.Number — как после канонического разбора, этого ждут intF/moneyF
	var a map[string]any
	err := d.Decode(&a)
	return a, err
}

// Авто-write в правах агента: поля необязательные (старое приложение их не шлёт), а при write_without_confirm=true
// срок write_auto_until обязателен. Канонический разбор — как у приложения (числа как json.Number).
func TestAgentRightsWriteAuto(t *testing.T) {
	const env = `"agent":"fugu","device_id":"d-6UoWwDCkLjV0J-pQ","limit_usd_month":null,"nonce":"vector-nonce-000000015","servers":["prod-1"],"space":"u-anna","ts":1790856000,"type":"agent_rights"`
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"без новых полей (старое приложение)", `{"read_without_confirm":true,` + env + `}`, true},
		{"write-авто со сроком", `{"read_without_confirm":true,"write_auto_until":1790859600,"write_without_confirm":true,` + env + `}`, true},
		{"write-авто без срока", `{"read_without_confirm":true,"write_without_confirm":true,` + env + `}`, false},
		{"срок без флага — допустимо (флаг выключен)", `{"read_without_confirm":true,"write_auto_until":1790859600,"write_without_confirm":false,` + env + `}`, true},
		{"срок не число", `{"read_without_confirm":true,"write_auto_until":"скоро","write_without_confirm":true,` + env + `}`, false},
		{"лишнее неизвестное поле", `{"read_without_confirm":true,"wat":1,` + env + `}`, false},
	}
	for _, c := range cases {
		a, err := parseNum([]byte(c.body))
		if err == nil {
			err = ValidateAction(a)
		}
		if c.ok && err != nil {
			t.Errorf("%s: отклонено, ждали приём: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: принято, ждали отказ", c.name)
		}
		if !c.ok && err != nil && !errors.Is(err, ErrBadAction) {
			t.Errorf("%s: не та ошибка: %v", c.name, err)
		}
	}
}
