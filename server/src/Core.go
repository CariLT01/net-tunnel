package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

var RATE_LIMIT_MBPS = 200_000_000
var RATE_LIMIT_BURST_MBPS = 500_000_000

type WebsocketConnection struct {
	connection   *websocket.Conn
	writeMutex   sync.Mutex
	sharedSecret []byte

	handshakeTranscript []byte
	ready               bool
}

type TCPConnection struct {
	conn *net.Conn

	ExpectedSequenceID atomic.Int64
	QueuedPackets      map[int64][]byte
	QueuedPacketsMu    sync.RWMutex

	SendSequenceId atomic.Int64
}

type Session struct {
	clientIDs        map[int]*TCPConnection
	clientIDsMu      sync.RWMutex
	wssConnections   []*WebsocketConnection
	wssConnectionsMu sync.RWMutex
	lastActiveTime   time.Time
	clientsActive    atomic.Int32

	outboundLimiter    *rate.Limiter
	roundRobinIterator atomic.Int64
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
		outboundLimiter:  rate.NewLimiter(rate.Limit(RATE_LIMIT_MBPS/8), RATE_LIMIT_BURST_MBPS/8),
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
