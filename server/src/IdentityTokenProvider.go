package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type IdentityTokenProvider struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

type IdentityTokenClaims struct {
	SessionId int `json:"sessionId"`
	jwt.RegisteredClaims
}

func NewIdentityTokenProvider() *IdentityTokenProvider {
	privateKey, publicKey := GenerateKeypair()

	return &IdentityTokenProvider{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

func (provider *IdentityTokenProvider) CreateIdentityToken(sessionId int) (string, error) {
	claims := IdentityTokenClaims{
		SessionId: sessionId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 2)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "LETServer",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	return token.SignedString(provider.privateKey)
}

func (provider *IdentityTokenProvider) ParseIdentityToken(tokenString string) (*IdentityTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &IdentityTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return provider.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*IdentityTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (provider *IdentityTokenProvider) VerifyIdentityToken(token string, sessionId int) bool {
	claims, err := provider.ParseIdentityToken(token)
	if err != nil {
		log.Print("detected invalid identity token")
		return false
	}

	if claims.SessionId != sessionId {
		log.Print("session ID does not match")
		return false
	}

	return true
}
