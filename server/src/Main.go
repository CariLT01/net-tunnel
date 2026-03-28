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
	log.Print("serving")
	http.ListenAndServe("127.0.0.1:8682", nil)
}
