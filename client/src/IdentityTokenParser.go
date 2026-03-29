package main

import (
	"crypto/ed25519"
	"fmt"
	"log"

	"github.com/golang-jwt/jwt/v5"
)

type IdentityTokenClaims struct {
	SessionId int `json:"sessionId"`
	jwt.RegisteredClaims
}

func ParseIdentityToken(tokenString string, publicKey ed25519.PublicKey) (*IdentityTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &IdentityTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*IdentityTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func VerifyIdentityToken(token string, sessionId int, publicKey ed25519.PublicKey) bool {
	claims, err := ParseIdentityToken(token, publicKey)
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
