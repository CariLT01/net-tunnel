package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

func main() {
	// Generate keypair
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// Encode to base64
	privB64 := base64.StdEncoding.EncodeToString(privKey)
	pubB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Print results
	fmt.Println("Private Key (Base64):", privB64)
	fmt.Println("Public Key  (Base64):", pubB64)
}
