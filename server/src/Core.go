package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type WebsocketConnection struct {
	connection   *websocket.Conn
	writeMutex   sync.Mutex
	sharedSecret []byte
}

type Session struct {
	clientIDs        map[int]*net.Conn
	clientIDsMu      sync.RWMutex
	wssConnections   []*WebsocketConnection
	wssConnectionsMu sync.RWMutex
	lastActiveTime   time.Time
	clientsActive    atomic.Int32
}

type Server struct {
	upgrader   *websocket.Upgrader
	sessions   map[int]*Session
	sessionsMu sync.RWMutex
}

func NewSession() *Session {
	return &Session{
		clientIDs:        make(map[int]*net.Conn),
		clientIDsMu:      sync.RWMutex{},
		lastActiveTime:   time.Now(),
		clientsActive:    atomic.Int32{},
		wssConnections:   make([]*WebsocketConnection, 0),
		wssConnectionsMu: sync.RWMutex{},
	}
}

func NewServer() *Server {
	return &Server{
		upgrader: &websocket.Upgrader{
			ReadBufferSize:  65536,
			WriteBufferSize: 65536,
		},
		sessions:   make(map[int]*Session),
		sessionsMu: sync.RWMutex{},
	}
}
