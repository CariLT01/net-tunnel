package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/widget"
)

func fyneApp() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Hello Fyne")

	myWindow.SetContent(widget.NewLabel("Hello, World!"))
	myWindow.ShowAndRun()
}

func main() {

	go fyneApp()

	fmt.Println("--- Lightweight encrypted tunnel ---")
	fmt.Println("info:")
	fmt.Println(" - protocol: WSS/custom")
	fmt.Println(" - encryption: TLS + custom encryption layer: post-quantum kyber768 handshake + AES-256-GCM post-quantum resistant")
	fmt.Println(" - load distribution: relocatable streams, load-based dist: number of tcp connections on wss stream")
	fmt.Println(" - failure handler: relocate stream, inbound/outbound can be on separate streams")
	fmt.Println(" - multiplexing scaling: scale down: <6 socket/stream avg / scale up: >12 socket/stream avg")
	fmt.Println(" - multiplexing layer: min 2, max ", NUMBER_OF_CONNECTIONS, " concurrent wss streams")
	fmt.Println(" - limit: 256 concurrent tcp streams")

	fmt.Println("\n\n\nLoading...")
	time.Sleep(2 * time.Second)

	connectionHandler := NewConnectionHandler()

	log.Print("initializing connection handler")
	connectionHandler.Initialize()
	log.Print("initialized")

	ln, err := net.Listen("tcp", "127.0.0.1:5000")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("listening on 127.0.0.1:5000")

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go connectionHandler.HandleNewConnection(conn)
	}
}
