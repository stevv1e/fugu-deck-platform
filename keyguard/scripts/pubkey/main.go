// pubkey: закрытый ключ P-256 (hex) → публичный (несжатая точка, base64) — как печатает keyguard-hpke-init.sh.
package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	b, err := hex.DecodeString(os.Args[1])
	if err != nil {
		panic(err)
	}
	k, err := ecdh.P256().NewPrivateKey(b)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()))
}
