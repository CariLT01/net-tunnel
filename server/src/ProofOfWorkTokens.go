package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type PowTokenClaims struct {
	Salt          string `json:"salt"`
	Difficulty    int    `json:"difficulty"`
	ProofAudience string `json:"proofAudience"`
	jwt.RegisteredClaims
}

type PowEndpointResponse struct {
	Ok             bool    `json:"ok"`
	ChallengeToken *string `json:"challengeToken"`
}

func (server *ProofOfWorkVerifier) CreateProofOfWorkToken(salt string, audience string) (string, error) {
	log.Print("debug: difficulty is: ", server.difficulty)
	claims := PowTokenClaims{
		Salt:          salt,
		Difficulty:    server.difficulty,
		ProofAudience: audience,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 2)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "LETServer",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	return token.SignedString(server.privateKey)
}

func (server *ProofOfWorkVerifier) ParseProofOfWorkToken(tokenString string) (*PowTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &PowTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return *server.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*PowTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (server *ProofOfWorkVerifier) GenerateProofOfWorkSalt() (string, error) {
	unixTimeMilli := time.Now().UnixMilli()
	nonce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return "", err
	}

	saltString := strconv.FormatInt(unixTimeMilli, 10) + "/" + strconv.FormatInt(nonce.Int64(), 10)

	return saltString, nil
}

func (server *ProofOfWorkVerifier) GenerateProofOfWorkChallenge(audience string) (string, error) {
	salt, err := server.GenerateProofOfWorkSalt()

	if err != nil {
		return "", err
	}

	token, err := server.CreateProofOfWorkToken(salt, audience)
	if err != nil {
		return "", err
	}

	return token, nil
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

func (server *ProofOfWorkVerifier) VerifyProofOfWorkSolution(token string, nonce string, requiredAudience string) bool {
	claims, err := server.ParseProofOfWorkToken(token)
	if err != nil {
		log.Print("invalid pow token provided: ", err)
		return false
	}

	if claims.ProofAudience != requiredAudience {
		log.Print("wrong audience: ", claims.ProofAudience)
		return false
	}

	_, exists := server.usedSalts[claims.Salt]
	if exists {
		log.Print("salt already used")
		return false
	}

	nonceInt, err := strconv.Atoi(nonce)
	if err != nil {
		log.Print("unable to parse string to int: ", err)
		return false
	}

	// to bytes
	hashDataString := claims.Salt + "-" + strconv.Itoa(nonceInt)
	hashDataBytes := []byte(hashDataString)

	hash := sha256.Sum256(hashDataBytes)
	if hasLeadingZeroBits(hash[:], server.difficulty) {
		log.Print("proof of work is valid")
		server.usedSalts[claims.Salt] = struct{}{}
		return true
	} else {
		log.Print("proof of work is invalid")
		return false
	}
}

func (server *ProofOfWorkVerifier) marshalPowEndpointJsonResponse(success bool, challengeToken *string) (string, error) {
	res := PowEndpointResponse{Ok: success, ChallengeToken: challengeToken}
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	jsonString := string(jsonBytes)
	return jsonString, nil
}

func (server *ProofOfWorkVerifier) HandleProofOfWorkEndpoint(w http.ResponseWriter, r *http.Request) {

	values := r.URL.Query()

	proofOfWorkAudience := values.Get("audience")
	if proofOfWorkAudience != "session-creation" {
		log.Print("did not provide PoW audience")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "{\"ok\":false}")
		return
	}

	challengeToken, err := server.GenerateProofOfWorkChallenge("session-creation")
	if err != nil {
		log.Print("failed to generate proof of work challenge: ", err)
		json, err := server.marshalPowEndpointJsonResponse(false, nil)
		if err != nil {
			log.Print("failed to generate json: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "{\"ok\":false}")
			return
		} else {
			log.Print("failed to gen challenge: ", err)
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, json)
			return
		}
	} else {
		json, err := server.marshalPowEndpointJsonResponse(true, &challengeToken)
		if err != nil {
			log.Print("failed to generate json: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "{\"ok\":false}")
			return
		} else {
			log.Print("generated challenge token: ", challengeToken)
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, json)
			return
		}
	}
}
