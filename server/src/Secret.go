package main

import (
	"crypto/ed25519"
	"crypto/rand"
)

func GenerateSecureSecret() ([]byte, error) {
	key := make([]byte, 32) // 32 bytes for 256 bits
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateKeypair() (ed25519.PrivateKey, ed25519.PublicKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return priv, pub
}
