package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

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

func (server *ProofOfWorkVerifier) marshalPowEndpointJsonResponse(success bool, message string, challengeToken *string) string {
	res := PowEndpointResponse{Ok: success, ChallengeToken: challengeToken, Message: message}
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return ""
	}
	jsonString := string(jsonBytes)
	return jsonString
}

func (server *ProofOfWorkVerifier) allow(clientIP string) bool {
	cl, exists := server.challengeLimiters[clientIP]
	if !exists {
		cl = &ClientChallengeRequestLimiter{
			limiter:  rate.NewLimiter(rate.Every(time.Minute/5), 5),
			lastSeen: time.Now(),
		}
		server.challengeLimiters[clientIP] = cl
	}

	cl.lastSeen = time.Now()

	return cl.limiter.Allow()
}

func (server *ProofOfWorkVerifier) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// can contain multiple IPs: client, proxy1, proxy2
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (server *ProofOfWorkVerifier) HandleProofOfWorkEndpoint(w http.ResponseWriter, r *http.Request) {

	allowed := server.allow(server.getClientIP(r))
	if !allowed {
		log.Print("exceeded rate limit")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintln(w, server.marshalPowEndpointJsonResponse(false, "Rate limit exceeded, please try again later.", nil))
		return
	}

	values := r.URL.Query()

	proofOfWorkAudience := values.Get("audience")
	if proofOfWorkAudience != "session-creation" {
		log.Print("did not provide PoW audience")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, server.marshalPowEndpointJsonResponse(false, "No challenge audience provided", nil))
		return
	}

	challengeToken, err := server.GenerateProofOfWorkChallenge("session-creation")
	if err != nil {
		log.Print("failed to generate proof of work challenge: ", err)
		json := server.marshalPowEndpointJsonResponse(false, "Failed to generate a challenge", nil)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, json)
	} else {
		json := server.marshalPowEndpointJsonResponse(true, "OK", &challengeToken)
		log.Print("generated challenge token: ", challengeToken)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, json)
		return
	}
}
