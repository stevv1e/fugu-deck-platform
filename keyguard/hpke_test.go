package keyguard

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type hv struct {
	Info, SkRm, PkRm, SkEm, Enc, SharedSecret, Key, BaseNonce string
	Encryptions                                               []struct{ Aad, Ct, Nonce, Pt string }
}

func (v *hv) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	s := func(k string) string { var x string; json.Unmarshal(m[k], &x); return x }
	v.Info, v.SkRm, v.PkRm, v.SkEm, v.Enc = s("info"), s("skRm"), s("pkRm"), s("skEm"), s("enc")
	v.SharedSecret, v.Key, v.BaseNonce = s("shared_secret"), s("key"), s("base_nonce")
	return json.Unmarshal(m["encryptions"], &v.Encryptions)
}

func hx(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Официальные тест-векторы RFC 9180 для нашего набора: обе стороны, побайтно.
func TestHPKE_RFC9180Vectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/hpke-p256-base.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []hv
	if err := json.Unmarshal(raw, &vs); err != nil || len(vs) == 0 {
		t.Fatalf("векторы: %v", err)
	}
	for _, v := range vs {
		skR, _ := ecdh.P256().NewPrivateKey(hx(t, v.SkRm))
		if !bytes.Equal(skR.PublicKey().Bytes(), hx(t, v.PkRm)) {
			t.Fatal("pkR не совпал")
		}
		// получатель: shared_secret, key, base_nonce
		pkE, _ := ecdh.P256().NewPublicKey(hx(t, v.Enc))
		dh, _ := skR.ECDH(pkE)
		ss := extractAndExpand(dh, append(hx(t, v.Enc), hx(t, v.PkRm)...))
		if !bytes.Equal(ss, hx(t, v.SharedSecret)) {
			t.Fatal("shared_secret не совпал")
		}
		key, nonce := keySchedule(ss, hx(t, v.Info))
		if !bytes.Equal(key, hx(t, v.Key)) || !bytes.Equal(nonce, hx(t, v.BaseNonce)) {
			t.Fatal("key/base_nonce не совпали")
		}
		g, _ := gcm(key)
		for i, e := range v.Encryptions {
			n := nonceSeq(nonce, uint64(i))
			if !bytes.Equal(n, hx(t, e.Nonce)) {
				t.Fatalf("nonce seq %d", i)
			}
			if ct := g.Seal(nil, n, hx(t, e.Pt), hx(t, e.Aad)); !bytes.Equal(ct, hx(t, e.Ct)) {
				t.Fatalf("ct seq %d не совпал", i)
			}
		}
		// отправитель с эфемерным ключом из вектора + наш HPKEOpen на первом сообщении
		skE, _ := ecdh.P256().NewPrivateKey(hx(t, v.SkEm))
		e0 := v.Encryptions[0]
		enc, ct, err := hpkeSealWith(skE, skR.PublicKey(), hx(t, v.Info), hx(t, e0.Aad), hx(t, e0.Pt))
		if err != nil || !bytes.Equal(enc, hx(t, v.Enc)) || !bytes.Equal(ct, hx(t, e0.Ct)) {
			t.Fatal("HPKESeal не совпал с вектором")
		}
		pt, err := HPKEOpen(skR, hx(t, v.Enc), hx(t, v.Info), hx(t, e0.Aad), hx(t, e0.Ct))
		if err != nil || !bytes.Equal(pt, hx(t, e0.Pt)) {
			t.Fatal("HPKEOpen не совпал с вектором")
		}
		t.Logf("RFC 9180: shared_secret, key, base_nonce, %d шифротекстов — совпали", len(v.Encryptions))
	}
}
