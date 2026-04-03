package main

import (
	"log"
	"net/http"
)

func main() {

	server := NewServer()
	go server.HandleSessionsCleanup()
	http.HandleFunc("/stream", server.HandleWebsocketRequest)
	http.HandleFunc("/session/create", server.HandleSessionCreationRequest)
	http.HandleFunc("/challenge/generate", server.verifier.HandleProofOfWorkEndpoint)
	http.HandleFunc("/keys", server.HandleKeysEndpoint)
	log.Print("serving")
	http.ListenAndServe(":10000", nil)
}
