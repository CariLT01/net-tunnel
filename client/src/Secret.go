package main

import "crypto/rand"

func GenerateSecureSecret() ([]byte, error) {
	key := make([]byte, 32) // 32 bytes for 256 bits
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
