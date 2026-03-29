package main

import (
	"crypto/ed25519"
)

type ProofOfWorkVerifier struct {
	privateKey *ed25519.PrivateKey
	publicKey  *ed25519.PublicKey

	usedSalts  map[string]struct{}
	difficulty int
}

func NewProofOfWorkVerifier() *ProofOfWorkVerifier {

	privateKey, publicKey := GenerateKeypair()

	return &ProofOfWorkVerifier{
		privateKey: &privateKey,
		publicKey:  &publicKey,
		usedSalts:  make(map[string]struct{}),
		difficulty: 24,
	}
}
