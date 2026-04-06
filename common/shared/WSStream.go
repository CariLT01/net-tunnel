package shared

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/gorilla/websocket"
)

type HandshakeProtocolCompletion struct {
	KyberHandshakeReceived  bool
	SignatureReceived       bool
	KeyConfirmationReceived bool
	ClientHelloReceived     bool
	KeyConfirmed            bool
	EncryptionEstablished   bool
}

type WSStream struct {
	ready                     atomic.Bool
	handshakeSucceeded        atomic.Bool
	intentionallyDisconnected atomic.Bool
	connection                *websocket.Conn
	writeMutex                sync.Mutex
	connectedCount            atomic.Int64
	sharedSecret              []byte

	handshakeTranscript []byte

	protocolCompletion HandshakeProtocolCompletion
	scheme             kem.Scheme

	Index           uint32
	Latency         atomic.Uint32
	LatencyPingTime time.Time
}

func (stream *WSStream) WriteRaw(rawData []byte) error {
	stream.writeMutex.Lock()
	err := stream.connection.WriteMessage(websocket.BinaryMessage, rawData)
	stream.writeMutex.Unlock()
	return err
}

func (stream *WSStream) WriteData(rawData []byte) error {
	if stream.ready.Load() {
		// encrypt
		log.Print("ready is true, encrypting: ", rawData)
		encryptedData, err := Encrypt(stream.sharedSecret, rawData)
		if err != nil {
			log.Print("failed to encrypt! DEBUG PLEASE REMOVE LATER secret: ", stream.sharedSecret)
			return err
		}
		log.Print("encrypting data")

		err = stream.WriteRaw(encryptedData)
		return err
	} else {
		log.Print("ready isn't true, not encrypting: ", rawData)
		// write directly
		err := stream.WriteRaw(rawData)
		return err
	}
}
func (stream *WSStream) DecodeReadData(rawData []byte) ([]byte, error) {
	if stream.ready.Load() {

		decryptedData, err := Decrypt(stream.sharedSecret, rawData)
		if err != nil {
			return nil, err
		}
		return decryptedData, nil
	} else {
		return rawData, nil
	}
}

func (stream *WSStream) Close() error {
	return stream.connection.Close()
}

func (stream *WSStream) SetReady(ready bool) { stream.ready.Store(ready) }

func (stream *WSStream) GetConnection() *websocket.Conn {
	return stream.connection
}

func (stream *WSStream) GetReady() bool {
	return stream.ready.Load()
}
func (stream *WSStream) GetScheme() kem.Scheme {
	return stream.scheme
}

func (stream *WSStream) AppendToTranscript(data []byte) {
	stream.handshakeTranscript = append(stream.handshakeTranscript, data...)
}
func (stream *WSStream) GetHandshakeTranscript() []byte { return stream.handshakeTranscript }

func (stream *WSStream) SetSharedSecret(secret []byte) {
	stream.sharedSecret = secret
}
func (stream *WSStream) GetSharedSecret() []byte { return stream.sharedSecret }

func (stream *WSStream) GetProtocolCompletion() *HandshakeProtocolCompletion {
	return &stream.protocolCompletion
}

func (stream *WSStream) SetHandshakeSucceeded(v bool) {
	stream.handshakeSucceeded.Store(v)
}

func (stream *WSStream) GetHandshakeSucceeded() bool { return stream.handshakeSucceeded.Load() }

func (stream *WSStream) SetIntentionallyDisconnected(v bool) {
	stream.intentionallyDisconnected.Store(v)
}

func (stream *WSStream) GetIntentionallyDisconnected() bool {
	return stream.intentionallyDisconnected.Load()
}
