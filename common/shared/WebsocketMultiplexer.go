package shared

import (
	"encoding/binary"
	"fmt"
	"log"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/gorilla/websocket"
)

type ToRetry struct {
	Data         []byte
	FirstIndex   uint32
	CurrentIndex uint32
}

type UnacknowledgedPacket struct {
	WebsocketIndex uint32
	Payload        []byte
}

type WebsocketMultiplexer struct {
	Streams               map[uint32]*WSStream
	StreamCounter         atomic.Uint32
	StreamsMu             sync.RWMutex
	ActiveStreamIndexes   []uint32
	ActiveStreamIndexesMu sync.RWMutex

	/* SIGNAL STREAMS */
	SignalSequenceId        atomic.Uint32
	SignalRoundRobinCounter atomic.Uint32

	/* DATA STREAMS */
	DataStreamRoundRobinCounter atomic.Uint32

	// Reorder signal streams
	SignalExpectedSeqId atomic.Uint32
	SignalUnorderedMu   sync.RWMutex
	SignalUnordered     map[uint32]*SignalDecodedPacket

	/* RESEND */
	QueuedForResend [][]byte   // Retry when a connection establishes again
	QuickRetryQueue []*ToRetry // Retry on the next "retry" tick

	/* Unacknowledged packets */
	UnacknowledgedPackets map[uint32]*UnacknowledgedPacket
	// tracks the total sequence ID of the ENTIRE multiplexer
	// unlike signal seq id or tcp stream seq id, this seq id
	// DOES NOT reorder packets. This seq id is ONLY for
	// allowing for ACK to work and correct retransmission
	MultiplexerSequenceID atomic.Uint32

	/* GLOBAL HANDSHAKE STATE */
	Ready atomic.Bool
	ProtocolCompletion *HandshakeProtocolCompletion
	HandshakeTranscript []byte

	Scheme kem.Scheme

	SessionEnded atomic.Bool

	/* don't want the school to see what you're doing */
	SharedSecret []byte
	PublicKey *kyber768.PublicKey
	PrivateKey *kyber768.PrivateKey
	

}

/* 
Packet format:

4 bytes multiplexer sequence ID
1 byte messageType
4 bytes message size
...payload
*/

type PreprocessedPacket struct {
	MessageType MessageType
	Payload     []byte
}

type DecodedPacket struct {
	MessageType MessageType
	Payload []byte
	SequenceId uint32
}

type SignalDecodedPacket struct {
	MessageType MessageType
	Payload []byte
	SequenceId uint32
	SignalSequenceId uint32
}

func NewWebsocketMultiplexer() *WebsocketMultiplexer {
	return &WebsocketMultiplexer{
		Streams:          make(map[uint32]*WSStream),
		SignalSequenceId: atomic.Uint32{},
	}
}

func (multiplexer *WebsocketMultiplexer) EncodePacket(messageType MessageType, payload []byte) []byte {
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(len(payload)))

	finalBuffer := append(append([]byte{messageType}, sizeBuf...), payload...)

	return finalBuffer
}

func (multiplexer *WebsocketMultiplexer) SendDataOnAnyWithIndex(currentCounter uint32, payload []byte) {
	multiplexer.ActiveStreamIndexesMu.RLock()
	activeStreamsCount := len(multiplexer.ActiveStreamIndexes)

	if activeStreamsCount <= 0 {
		log.Print("error: Unable to send data! No active connections")

		multiplexer.QueuedForResend = append(multiplexer.QueuedForResend, payload)
		multiplexer.ActiveStreamIndexesMu.RUnlock()
		return
	}
	targetStreamIndex := multiplexer.ActiveStreamIndexes[currentCounter%uint32(activeStreamsCount)]
	multiplexer.ActiveStreamIndexesMu.RUnlock()
	multiplexer.StreamsMu.RLock()
	targetStream := multiplexer.Streams[targetStreamIndex]
	multiplexer.StreamsMu.RUnlock()

	seqIdBuf := make([]byte, 4)
	currentDataSeqId := multiplexer.MultiplexerSequenceID.Add(1) - 1
	log.Print("debug: sending data on sequence index ", currentDataSeqId)
	binary.BigEndian.PutUint32(seqIdBuf, currentDataSeqId)

	encodedPayload := append(seqIdBuf, payload...)

	err := targetStream.WriteData(encodedPayload)
	if err != nil {
		log.Print("error: failed to write: queueing to quick retry queue")
		multiplexer.QuickRetryQueue = append(multiplexer.QuickRetryQueue, &ToRetry{
			FirstIndex:   targetStreamIndex,
			CurrentIndex: targetStreamIndex,
			Data:         encodedPayload,
		})
	} else {
		multiplexer.UnacknowledgedPackets[currentDataSeqId] = &UnacknowledgedPacket{
			WebsocketIndex: targetStreamIndex,
			Payload:        encodedPayload,
		}
	}
}

func (multiplexer *WebsocketMultiplexer) SendSignalRawOnAny(payload []byte) {
	currentCounter := multiplexer.SignalRoundRobinCounter.Load()
	multiplexer.SignalRoundRobinCounter.Add(1)

	multiplexer.SendDataOnAnyWithIndex(currentCounter, payload)
}

func (multiplexer *WebsocketMultiplexer) SendDataRawOnAny(payload []byte) {
	currentCounter := multiplexer.DataStreamRoundRobinCounter.Load()
	multiplexer.DataStreamRoundRobinCounter.Add(1)

	multiplexer.SendDataOnAnyWithIndex(currentCounter, payload)
}

func (multiplexer *WebsocketMultiplexer) SendSignal(messageType MessageType, data []byte) {
	// encode pckt
	seqIdBuf := make([]byte, 4)
	seqIdCurrent := multiplexer.SignalSequenceId.Load()
	multiplexer.SignalSequenceId.Add(1)
	binary.BigEndian.PutUint32(seqIdBuf, seqIdCurrent)

	payloadPacket := append(seqIdBuf, data...)

	encodedPacket := multiplexer.EncodePacket(messageType, payloadPacket)
	multiplexer.SendSignalRawOnAny(encodedPacket)
}

func (multiplexer *WebsocketMultiplexer) SendData(messageType MessageType, data []byte) {
	encodedPacket := multiplexer.EncodePacket(messageType, data)
	multiplexer.SendDataRawOnAny(encodedPacket)
}



func (multiplexer *WebsocketMultiplexer) PacketPreprocess(rawDecryptedData []byte) *PreprocessedPacket {
	messageType := rawDecryptedData[0]
	sizeBuf := rawDecryptedData[1:5]
	sizeInt := binary.BigEndian.Uint32(sizeBuf)
	payload := rawDecryptedData[5 : 5+sizeInt]

	return &PreprocessedPacket{
		MessageType: messageType,
		Payload:     payload,
	}
}

func (multiplexer *WebsocketMultiplexer) NewWebsocketStream(conn *websocket.Conn) *WSStream {
	currentIndex := multiplexer.StreamCounter.Add(1) - 1
	return &WSStream{
		ready:                     atomic.Bool{},
		handshakeSucceeded:        atomic.Bool{},
		intentionallyDisconnected: atomic.Bool{},
		connection:                conn,
		writeMutex:                sync.Mutex{},
		connectedCount:            atomic.Int64{},
		sharedSecret:              make([]byte, 0),

		handshakeTranscript: make([]byte, 0),

		protocolCompletion: HandshakeProtocolCompletion{
			KyberHandshakeReceived:  false,
			SignatureReceived:       false,
			KeyConfirmationReceived: false,
		},
		scheme: kyber768.Scheme(),

		Index: currentIndex,
	}
}

func (multiplexer *WebsocketMultiplexer) AddWebsocketStream(stream *WSStream) {
	multiplexer.StreamsMu.Lock()
	multiplexer.Streams[stream.Index] = stream
	multiplexer.StreamsMu.Unlock()
}

func (multiplexer *WebsocketMultiplexer) DeleteWebsocketStream(stream *WSStream) {
	multiplexer.StreamsMu.Lock()
	delete(multiplexer.Streams, stream.Index)
	multiplexer.StreamsMu.Unlock()
}

func (multiplexer *WebsocketMultiplexer) SetActive(stream *WSStream) {
	multiplexer.ActiveStreamIndexesMu.Lock()
	multiplexer.ActiveStreamIndexes = append(multiplexer.ActiveStreamIndexes, stream.Index)
	multiplexer.ActiveStreamIndexesMu.Unlock()
}

func (multiplexer *WebsocketMultiplexer) SetInactive(stream *WSStream) error {
	multiplexer.ActiveStreamIndexesMu.Lock()
	defer multiplexer.ActiveStreamIndexesMu.Unlock()
	index := slices.Index(multiplexer.ActiveStreamIndexes, stream.Index)
	if index == -1 {
		return fmt.Errorf("Index not found")
	}
	multiplexer.ActiveStreamIndexes = slices.Delete(multiplexer.ActiveStreamIndexes, index, index+1)

	return nil
}

func (multiplexer *WebsocketMultiplexer) SendAcknowledged(seqId uint32) {
	// Send acknowledged packet
	log.Print("debug: acknowledged packet sequence #", seqId)

	acknowledgedSeqIdBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(acknowledgedSeqIdBuf, seqId)
	multiplexer.SendSignal(MessageTypeAcknowledged, acknowledgedSeqIdBuf)
}

func (multiplexer *WebsocketMultiplexer) DecodePacket(decryptedData []byte) *DecodedPacket {
	// 4 multiplexer seq id 1 msg type 4 msg size ...payload
	// in the case of signal packets, there will be an additional 4 bytes for signal sequencer id

	messageMpSeqIdBuf := decryptedData[:4]
	messageType := decryptedData[4]
	messageSizeBuf := decryptedData[5:9]
	messageSizeInt := binary.BigEndian.Uint32(messageSizeBuf)

	messagePayload := decryptedData[9:9 + messageSizeInt]

	mpSeqId := binary.BigEndian.Uint32(messageMpSeqIdBuf)

	return &DecodedPacket{
		MessageType: messageType,
		Payload: messagePayload,
		SequenceId: mpSeqId,
	}
}

func (multiplexer *WebsocketMultiplexer) DecodedSignalPacket(predecodedPacket *DecodedPacket) *SignalDecodedPacket {
	// decodes the additional 4 bytes for SIGNAL

	messageSignalSequenceIdBuf := predecodedPacket.Payload[:4]
	messagePayload := predecodedPacket.Payload[5:]

	signalSeqId := binary.BigEndian.Uint32(messageSignalSequenceIdBuf)

	return &SignalDecodedPacket{
		MessageType: predecodedPacket.MessageType,
		Payload: messagePayload,
		SequenceId: predecodedPacket.SequenceId,
		SignalSequenceId: signalSeqId,
	}
}

func (multiplexer *WebsocketMultiplexer) Disconnect() {
	multiplexer.SessionEnded.Store(true)

	for _, connection := range multiplexer.Streams {
		connection.Close()
	}
}
