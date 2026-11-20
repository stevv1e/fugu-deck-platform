package keyguard

// Общие векторы с приложением: канонические байты и JWS создаёт код модуля deck-security
// (fugu-deck-stage0/e2e/vectors.ts). keyguard обязан принять каждый — так формат подписи не расходится.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func TestActionVectors_FromApp(t *testing.T) {
	raw, err := os.ReadFile("testdata/action-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		DeviceID string                `json:"device_id"`
		TS       int64                 `json:"ts"`
		JWK      struct{ X, Y string } `json:"confirm_jwk"`
		Vectors  []struct{ Name, Canonical, JWS string }
		Invalid  []struct{ Name, Canonical string }
	}
	if err := json.Unmarshal(raw, &f); err != nil || len(f.Vectors) == 0 {
		t.Fatalf("векторы: %v", err)
	}
	x, _ := b64u.DecodeString(f.JWK.X)
	y, _ := b64u.DecodeString(f.JWK.Y)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	devs := NewDevices()
	devs.Add(&Device{ID: f.DeviceID, User: "anna", ConfirmPub: pub})
	v := &Verifier{Devices: devs, Nonces: NewNonces(), Now: func() time.Time { return time.Unix(f.TS, 0) }}
	for _, vec := range f.Vectors {
		a, err := ParseCanonical([]byte(vec.Canonical))
		if err != nil {
			t.Errorf("%s: канонические байты приложения не приняты: %v", vec.Name, err)
			continue
		}
		if got := string(Canonical(a)); got != vec.Canonical {
			t.Errorf("%s: Go канонизирует иначе:\n app: %s\n go:  %s", vec.Name, vec.Canonical, got)
		}
		typ := s(a, "type")
		got, dev, err := v.Verify(SignedAction{JWS: vec.JWS}, typ)
		if err != nil || dev.ID != f.DeviceID || s(got, "type") != typ {
			t.Errorf("%s: JWS приложения не принят: %v", vec.Name, err)
			continue
		}
		if _, _, err := v.Verify(SignedAction{JWS: vec.JWS}, typ); err != ErrReplay {
			t.Errorf("%s: повтор принят (%v)", vec.Name, err)
		}
		// подмена одного символа payload ломает подпись
		p := strings.Split(vec.JWS, ".")
		pl, _ := b64u.DecodeString(p[1])
		bad := p[0] + "." + b64u.EncodeToString([]byte(strings.Replace(string(pl), `"ts":`, `"ts":1`, 1))) + "." + p[2]
		if _, _, err := v.Verify(SignedAction{JWS: bad}, typ); err == nil {
			t.Errorf("%s: изменённый payload принят", vec.Name)
		}
	}
	// Конверты, которые отклоняет схема приложения, обязана отклонить и схема keyguard (на разборе или на проверке полей).
	if len(f.Invalid) == 0 {
		t.Error("в файле нет невалидных векторов")
	}
	for _, vec := range f.Invalid {
		a, err := ParseCanonical([]byte(vec.Canonical))
		if err == nil {
			err = ValidateAction(a)
		}
		if err == nil {
			t.Errorf("%s: keyguard ПРИНЯЛ конверт, который приложение отклоняет: %s", vec.Name, vec.Canonical)
		}
	}
	// у каждого типа схемы есть хотя бы один принятый вектор — новый тип нельзя добавить только в keyguard
	seen := map[string]bool{}
	for _, vec := range f.Vectors {
		a, _ := ParseCanonical([]byte(vec.Canonical))
		seen[s(a, "type")] = true
	}
	for typ := range actionSchemas {
		if !seen[typ] {
			t.Errorf("тип %q есть в схеме keyguard, но нет вектора из приложения", typ)
		}
	}
	t.Logf("векторы приложения: %d приняты, %d отклонены", len(f.Vectors), len(f.Invalid))
}
