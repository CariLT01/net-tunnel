package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

func init() {
	file, err := os.OpenFile(
		"server.log",
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0666,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Write to both file and stdout
	mw := io.MultiWriter(os.Stdout, file)

	log.SetOutput(mw)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

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
