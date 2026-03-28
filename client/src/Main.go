package main

import (
	"fmt"
	"log"
	"net"
)

func main() {

	connectionHandler := NewConnectionHandler()

	log.Print("initializing connection handler")
	connectionHandler.Initialize()
	log.Print("initialized")

	ln, err := net.Listen("tcp", "127.0.0.1:5000")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("Proxy listening on 127.0.0.1:5000")

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go connectionHandler.HandleNewConnection(conn)
	}
}
