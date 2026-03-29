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
}

type ProxyWebsocketConnection struct {
	ready          bool
	connection     *websocket.Conn
	writeMutex     sync.Mutex
	connectedCount atomic.Int64
	sharedSecret   []byte
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

	keys *Keys
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
	}
}
