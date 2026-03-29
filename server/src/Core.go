package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

type WebsocketConnection struct {
	connection   *websocket.Conn
	writeMutex   sync.Mutex
	sharedSecret []byte
}

type TCPConnection struct {
	conn *net.Conn
}

type Session struct {
	clientIDs        map[int]*TCPConnection
	clientIDsMu      sync.RWMutex
	wssConnections   []*WebsocketConnection
	wssConnectionsMu sync.RWMutex
	lastActiveTime   time.Time
	clientsActive    atomic.Int32

	outboundLimiter *rate.Limiter
}

type Server struct {
	upgrader   *websocket.Upgrader
	sessions   map[int]*Session
	sessionsMu sync.RWMutex

	verifier         *ProofOfWorkVerifier
	identityProvider *IdentityTokenProvider
}

func NewSession() *Session {
	return &Session{
		clientIDs:        make(map[int]*TCPConnection),
		clientIDsMu:      sync.RWMutex{},
		lastActiveTime:   time.Now(),
		clientsActive:    atomic.Int32{},
		wssConnections:   make([]*WebsocketConnection, 0),
		wssConnectionsMu: sync.RWMutex{},
		outboundLimiter:  rate.NewLimiter(rate.Limit(20_000_000/8), 50_000_000/8),
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

		verifier:         NewProofOfWorkVerifier(),
		identityProvider: NewIdentityTokenProvider(),
	}
}

type KeysField struct {
	Challenge *string `json:"challenge"`
	Identity  *string `json:"identity"`
}

type KeysEndpointResponse struct {
	Ok   bool       `json:"ok"`
	Keys *KeysField `json:"keys"`
}
