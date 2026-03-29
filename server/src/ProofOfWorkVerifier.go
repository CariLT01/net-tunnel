package main

import (
	"crypto/ed25519"
	"time"

	"golang.org/x/time/rate"
)

type ClientChallengeRequestLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type ProofOfWorkVerifier struct {
	privateKey *ed25519.PrivateKey
	publicKey  *ed25519.PublicKey

	usedSalts  map[string]struct{}
	difficulty int

	// PoW challenge limiters
	challengeLimiters map[string]*ClientChallengeRequestLimiter
}

func NewProofOfWorkVerifier() *ProofOfWorkVerifier {

	privateKey, publicKey := GenerateKeypair()

	return &ProofOfWorkVerifier{
		privateKey: &privateKey,
		publicKey:  &publicKey,
		usedSalts:  make(map[string]struct{}),
		difficulty: 24,

		challengeLimiters: make(map[string]*ClientChallengeRequestLimiter),
	}
}
