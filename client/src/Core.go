package main

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

type ProxyLocalConnection struct {
	localConnection    net.Conn
	wssConnectionIndex int
	destination        string
	wssConnectionid    int

	// Reordering
	sequenceId         atomic.Int64
	expectedSequenceId atomic.Int64
	queuedPackets      map[int64][]byte
	queuedPacketsMu    sync.RWMutex
}

type ProxyWebsocketConnection struct {
	ready                     atomic.Bool
	handshakeSucceeded        atomic.Bool
	intentionallyDisconnected atomic.Bool
	connection                *websocket.Conn
	writeMutex                sync.Mutex
	connectedCount            atomic.Int64
	sharedSecret              []byte

	handshakeTranscript []byte
}

type ConnectionHandler struct {
	wssConnections             []*ProxyWebsocketConnection
	localConnections           map[int]*ProxyLocalConnection
	localConnectionsMutex      sync.RWMutex
	wssConnectionsMutex        sync.RWMutex
	clientConnectionIDs        map[int]struct{}
	clientConnectionIDsRWMutex sync.RWMutex

	sessionId     int
	powSolver     *ProofOfWorkSolver
	identityToken string

	keys              *Keys
	config            *ConfigurationManager
	roundRobinCounter atomic.Int64

	activeConnectionIndexes   []int
	activeConnectionIndexesMu sync.RWMutex
}

type ProxyClient struct {
	connectionHandler *ConnectionHandler
}

func NewConnectionHandler() *ConnectionHandler {
	return &ConnectionHandler{
		wssConnections:             make([]*ProxyWebsocketConnection, 0),
		localConnections:           make(map[int]*ProxyLocalConnection),
		localConnectionsMutex:      sync.RWMutex{},
		wssConnectionsMutex:        sync.RWMutex{},
		clientConnectionIDs:        make(map[int]struct{}),
		clientConnectionIDsRWMutex: sync.RWMutex{},

		sessionId:     -1,
		powSolver:     &ProofOfWorkSolver{},
		identityToken: "",
		config:        NewConfigManager(),

		activeConnectionIndexes:   make([]int, 0),
		activeConnectionIndexesMu: sync.RWMutex{},
	}
}
