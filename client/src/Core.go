package main

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/CariLT01/net-tunnel-common/shared"
	"github.com/cloudflare/circl/kem"
	"github.com/gorilla/websocket"
)

type ProxyLocalConnection struct {
	localConnection net.Conn

	// Reordering
	sequenceId         atomic.Int64
	expectedSequenceId atomic.Int64
	queuedPackets      map[int64][]byte
	queuedPacketsMu    sync.RWMutex

	// Acknowledgement and retransmition
	toBeAcknowledgedPackets   map[int64][]byte
	toBeAcknowledgedPacketsMu sync.RWMutex
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

	scheme kem.Scheme
}

type ConnectionHandler struct {
	multiplexer                *shared.WebsocketMultiplexer
	localConnections           map[int]*shared.TCPStream
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

	// Retransmission
	toBeRetransmittedPackets [][]byte

	// Acknowledgement for SIGNALS
	toBeAcknowledgedSignalPackets   map[int64][]byte
	toBeAcknowledgedSignalPacketsMu sync.RWMutex

	currentSendSequenceId      atomic.Int64
	lastAcknowledgedSequenceId atomic.Int64
}

type ProxyClient struct {
	connectionHandler *ConnectionHandler
}

func NewConnectionHandler() *ConnectionHandler {
	return &ConnectionHandler{
		localConnections:           make(map[int]*shared.TCPStream),
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

		multiplexer: shared.NewWebsocketMultiplexer(),
	}
}
