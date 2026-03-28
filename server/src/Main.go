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
	http.ListenAndServe(":10000", nil)
}
