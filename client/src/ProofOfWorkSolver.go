package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
)

type ProofOfWorkSolver struct {
	publicKey ed25519.PublicKey
}

type PowTokenClaims struct {
	Salt          string `json:"salt"`
	Difficulty    int    `json:"difficulty"`
	ProofAudience string `json:"proofAudience"`
	jwt.RegisteredClaims
}

type PowEndpointResponse struct {
	Ok             bool    `json:"ok"`
	Message        string  `json:"message"`
	ChallengeToken *string `json:"challengeToken"`
}

func hasLeadingZeroBits(hash []byte, bits int) bool {
	fullBytes := bits / 8
	remainingBits := bits % 8

	// Check full zero bytes
	for i := 0; i < fullBytes; i++ {
		if hash[i] != 0 {
			return false
		}
	}

	// Check remaining bits
	if remainingBits > 0 {
		mask := byte(0xFF << (8 - remainingBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}

	return true
}

func (solver *ProofOfWorkSolver) SolveProofOfWork(salt string, difficulty int) int64 {
	nonce := int64(0)

	for {
		concatenatedString := salt + "-" + strconv.FormatInt(nonce, 10)
		strBytes := []byte(concatenatedString)

		hashBytes := sha256.Sum256(strBytes)
		if hasLeadingZeroBits(hashBytes[:], difficulty) {
			log.Print("solved proof of work: nonce: ", nonce)
			return nonce
		} else {
			nonce++
		}
	}
}

func (server *ProofOfWorkSolver) ParseProofOfWorkToken(tokenString string) (*PowTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &PowTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return server.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*PowTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (solver *ProofOfWorkSolver) SolveFromToken(token string) (int64, error) {
	claims, err := solver.ParseProofOfWorkToken(token)
	if err != nil {
		return -1, fmt.Errorf("cannot decode token")
	}

	nonce := solver.SolveProofOfWork(claims.Salt, claims.Difficulty)
	log.Print("solved ", nonce)

	return nonce, nil
}

func (solver *ProofOfWorkSolver) GetChallenge() (string, error) {
	u := url.URL{Scheme: SCHEME_HTTP, Host: RELAY_URL, Path: "/challenge/generate"}
	q := u.Query()
	q.Set("audience", "session-creation")
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		return "", fmt.Errorf("Failed to fetch challenge: %s", err)
	}

	var response PowEndpointResponse

	err = json.NewDecoder(resp.Body).Decode(&response)

	if err != nil {
		return "", fmt.Errorf("Unable to decode JSON: %s", err)
	}

	if !response.Ok {
		return "", fmt.Errorf("Failed to generate challenge: %s", response.Message)
	}

	if response.ChallengeToken == nil {
		return "", fmt.Errorf("No challenge token provided")
	}

	return *response.ChallengeToken, nil

}

func (solver *ProofOfWorkSolver) GetChallengeAndSolve(keys *Keys) (string, int64) {
	log.Print("fetching public key")
	solver.publicKey = keys.challengeKey
	challengeToken, err := solver.GetChallenge()
	if err != nil {
		log.Fatal("error: failed to solve challenge: failed to get challenge: ", err)
	}

	challengeTokenHash := sha256.Sum256([]byte(challengeToken))

	log.Printf("solving challenge: %x\n", challengeTokenHash)

	nonce, err := solver.SolveFromToken(challengeToken)
	if err != nil {
		log.Fatal("error: failed to solve challenge: ", err)
	}

	return challengeToken, nonce
}
