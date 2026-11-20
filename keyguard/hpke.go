package keyguard

// HPKE, RFC 9180: mode_base, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
// Только стандартная библиотека (в Go 1.22 нет crypto/hpke). Проверено официальными тест-векторами RFC
// (hpke_test.go): совпадают shared_secret, key, base_nonce и все шифротексты.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	kemID           = 0x0010
	kdfID           = 0x0001
	aeadID          = 0x0001
	nSecret, nK, nN = 32, 16, 12
)

var (
	suiteKEM  = append([]byte("KEM"), i2osp(kemID, 2)...)
	suiteHPKE = append(append(append([]byte("HPKE"), i2osp(kemID, 2)...), i2osp(kdfID, 2)...), i2osp(aeadID, 2)...)
)

func i2osp(v, n int) []byte {
	b := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, l int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < l; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:l]
}

func labeledExtract(suite []byte, salt []byte, label string, ikm []byte) []byte {
	in := append(append(append([]byte("HPKE-v1"), suite...), label...), ikm...)
	return hkdfExtract(salt, in)
}

func labeledExpand(suite, prk []byte, label string, info []byte, l int) []byte {
	in := append(append(append(append(i2osp(l, 2), "HPKE-v1"...), suite...), label...), info...)
	return hkdfExpand(prk, in, l)
}

func extractAndExpand(dh, kemContext []byte) []byte {
	prk := labeledExtract(suiteKEM, nil, "eae_prk", dh)
	return labeledExpand(suiteKEM, prk, "shared_secret", kemContext, nSecret)
}

func keySchedule(sharedSecret, info []byte) (key, baseNonce []byte) {
	pskIDHash := labeledExtract(suiteHPKE, nil, "psk_id_hash", nil)
	infoHash := labeledExtract(suiteHPKE, nil, "info_hash", info)
	ctx := append(append([]byte{0x00}, pskIDHash...), infoHash...) // mode_base = 0
	secret := labeledExtract(suiteHPKE, sharedSecret, "secret", nil)
	return labeledExpand(suiteHPKE, secret, "key", ctx, nK), labeledExpand(suiteHPKE, secret, "base_nonce", ctx, nN)
}

// hpkeSealWith — шифрование одним сообщением (seq=0) с заданным эфемерным ключом (для тест-векторов).
func hpkeSealWith(ephemeral *ecdh.PrivateKey, pkR *ecdh.PublicKey, info, aad, pt []byte) (enc, ct []byte, err error) {
	dh, err := ephemeral.ECDH(pkR)
	if err != nil {
		return nil, nil, err
	}
	enc = ephemeral.PublicKey().Bytes()
	ss := extractAndExpand(dh, append(append([]byte{}, enc...), pkR.Bytes()...))
	key, nonce := keySchedule(ss, info)
	g, err := gcm(key)
	if err != nil {
		return nil, nil, err
	}
	return enc, g.Seal(nil, nonce, pt, aad), nil
}

// HPKESeal — то, что делает приложение на телефоне: шифрует ключ API на публичный ключ keyguard.
func HPKESeal(pkR *ecdh.PublicKey, info, aad, pt []byte) (enc, ct []byte, err error) {
	return HPKESealRand(rand.Reader, pkR, info, aad, pt)
}

func HPKESealRand(r io.Reader, pkR *ecdh.PublicKey, info, aad, pt []byte) ([]byte, []byte, error) {
	e, err := ecdh.P256().GenerateKey(r)
	if err != nil {
		return nil, nil, err
	}
	return hpkeSealWith(e, pkR, info, aad, pt)
}

var ErrHPKE = errors.New("hpke: не удалось расшифровать")

// HPKEOpen — keyguard расшифровывает. Любая ошибка (подмена enc, ct, aad, info) → ErrHPKE.
func HPKEOpen(skR *ecdh.PrivateKey, enc, info, aad, ct []byte) ([]byte, error) {
	pkE, err := ecdh.P256().NewPublicKey(enc)
	if err != nil {
		return nil, ErrHPKE
	}
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, ErrHPKE
	}
	ss := extractAndExpand(dh, append(append([]byte{}, enc...), skR.PublicKey().Bytes()...))
	key, nonce := keySchedule(ss, info)
	g, err := gcm(key)
	if err != nil {
		return nil, ErrHPKE
	}
	pt, err := g.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrHPKE
	}
	return pt, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// nonceSeq — base_nonce XOR seq (для векторов с seq>0).
func nonceSeq(base []byte, seq uint64) []byte {
	n := append([]byte{}, base...)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	for i := 0; i < 8; i++ {
		n[len(n)-8+i] ^= s[i]
	}
	return n
}
