package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
)

type SessionManager struct {
}

type Keys struct {
	challengeKey ed25519.PublicKey
	identityKey  ed25519.PublicKey
}

type KeysField struct {
	Challenge *string `json:"challenge"`
	Identity  *string `json:"identity"`
}

type KeysEndpointResponse struct {
	Ok   bool       `json:"ok"`
	Keys *KeysField `json:"keys"`
}

func (solver *SessionManager) FetchPublicKey(config *ConfigurationManager) *Keys {
	u := url.URL{Scheme: config.config.HttpScheme, Host: config.config.VpnServer, Path: "/keys"}
	resp, err := http.Get(u.String())
	if err != nil {
		log.Fatal("Failed to fetch public keys: ", err)
		return nil
	}

	var response KeysEndpointResponse

	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		log.Fatal("invalid json: ", err)
		return nil
	}
	if !response.Ok {
		log.Fatal("server did not return ok")
		return nil
	}
	if response.Keys == nil {
		log.Fatal("no keys")
		return nil
	}
	if response.Keys.Challenge == nil {
		log.Fatal("no challenge key")
		return nil
	}

	keys := Keys{}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(*response.Keys.Challenge)
	if err != nil {
		log.Fatal("unable to decode public key base64")
		return nil
	}

	keys.challengeKey = ed25519.PublicKey(publicKeyBytes)

	publicKeyBytes2, err := base64.StdEncoding.DecodeString(*response.Keys.Identity)
	if err != nil {
		log.Fatal("unable to decode identity key")
		return nil
	}

	keys.identityKey = publicKeyBytes2

	return &keys
}
