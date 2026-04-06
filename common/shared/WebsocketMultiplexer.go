package shared

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/gorilla/websocket"
)

type ToRetry struct {
	Data               []byte
	FirstIndex         uint32
	CurrentIndex       uint32
	OriginalSequenceId uint32
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
	QueuedForResendMu sync.RWMutex
	QueuedForResend   [][]byte   // Retry when a connection establishes again
	QuickRetryQueue   []*ToRetry // Retry on the next "retry" tick
	QuickRetryQueueMu sync.RWMutex

	/* Unacknowledged packets */
	UnacknowledgedPackets  map[uint32]*UnacknowledgedPacket
	UnacknowledgedPacketMu sync.RWMutex
	// tracks the total sequence ID of the ENTIRE multiplexer
	// unlike signal seq id or tcp stream seq id, this seq id
	// DOES NOT reorder packets. This seq id is ONLY for
	// allowing for ACK to work and correct retransmission
	MultiplexerSequenceID atomic.Uint32

	/* GLOBAL HANDSHAKE STATE */
	Ready               atomic.Bool
	ProtocolCompletion  *HandshakeProtocolCompletion
	HandshakeTranscript []byte
	IsDoingHandshake    atomic.Bool

	Scheme kem.Scheme

	SessionEnded atomic.Bool

	/* don't want the school to see what you're doing */
	SharedSecret []byte
	PublicKey    *kyber768.PublicKey
	PrivateKey   *kyber768.PrivateKey

	StreamFile *os.File
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
	Payload     []byte
	SequenceId  uint32
}

type SignalDecodedPacket struct {
	MessageType      MessageType
	Payload          []byte
	SequenceId       uint32
	SignalSequenceId uint32
}

func NewWebsocketMultiplexer() *WebsocketMultiplexer {

	streamFile, err := os.Create("debugStream.log")

	if err != nil {
		log.Fatal("couldn't open streaming file")
	}

	return &WebsocketMultiplexer{
		Streams:               make(map[uint32]*WSStream),
		ActiveStreamIndexes:   make([]uint32, 0),
		SignalUnordered:       make(map[uint32]*SignalDecodedPacket),
		QueuedForResend:       make([][]byte, 0),
		QuickRetryQueue:       make([]*ToRetry, 0),
		UnacknowledgedPackets: make(map[uint32]*UnacknowledgedPacket),
		HandshakeTranscript:   make([]byte, 0),
		ProtocolCompletion: &HandshakeProtocolCompletion{
			KyberHandshakeReceived:  false,
			SignatureReceived:       false,
			KeyConfirmationReceived: false,
			ClientHelloReceived:     false,
			KeyConfirmed:            false,
			EncryptionEstablished:   false,
		},

		Scheme:     kyber768.Scheme(),
		StreamFile: streamFile,
	}
}

func (multiplexer *WebsocketMultiplexer) StreamInLog(data []byte, label string) {
	var b strings.Builder
	b.WriteString(label)
	b.WriteString("  > ")

	b.WriteString("[")
	for index, byte_ := range data {
		b.WriteString(strconv.Itoa(int(byte_)))
		if index != len(data)-1 {
			b.WriteString(", ")
		}
	}
	b.WriteString("]\n")

	multiplexer.StreamFile.WriteString(b.String())
}

func (multiplexer *WebsocketMultiplexer) EncodePacket(messageType MessageType, payload []byte) []byte {
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(len(payload)))

	finalBuffer := append(append([]byte{messageType}, sizeBuf...), payload...)

	return finalBuffer
}

func (multiplexer *WebsocketMultiplexer) EncodePayload(payload []byte, currentDataSeqId uint32) []byte {
	seqIdBuf := make([]byte, 4)
	log.Print("debug: sending data on sequence index ", currentDataSeqId)
	binary.BigEndian.PutUint32(seqIdBuf, currentDataSeqId)

	encodedPayload := append(seqIdBuf, payload...)

	multiplexer.StreamInLog(encodedPayload, "SEND")

	return encodedPayload
}

func (multiplexer *WebsocketMultiplexer) SendDataOnAnyWithIndex(currentCounter uint32, payload []byte, existingSeqId *uint32) {
	multiplexer.ActiveStreamIndexesMu.RLock()
	activeStreamsCount := len(multiplexer.ActiveStreamIndexes)

	if activeStreamsCount <= 0 {
		log.Print("error: Unable to send data! No active connections")

		multiplexer.QueuedForResend = append(multiplexer.QueuedForResend, payload)
		multiplexer.ActiveStreamIndexesMu.RUnlock()
		return
	}

	currentDataSeqId := uint32(0)
	if existingSeqId == nil {

		currentDataSeqId = multiplexer.MultiplexerSequenceID.Add(1) - 1
		log.Print("incremented seq id by 1 to: ", currentDataSeqId)
	} else {
		currentDataSeqId = *existingSeqId
	}
	encodedPayload := multiplexer.EncodePayload(payload, currentDataSeqId)

	targetStreamIndex := multiplexer.ActiveStreamIndexes[currentCounter%uint32(activeStreamsCount)]
	multiplexer.ActiveStreamIndexesMu.RUnlock()
	multiplexer.StreamsMu.RLock()
	targetStream, exists := multiplexer.Streams[targetStreamIndex]
	multiplexer.StreamsMu.RUnlock()

	if !exists {
		log.Print("error: failed to write, active stream index no longer exists")
		log.Print("queuing to quick retry")
		multiplexer.QuickRetryQueueMu.Lock()
		multiplexer.QuickRetryQueue = append(multiplexer.QuickRetryQueue, &ToRetry{
			FirstIndex:         targetStreamIndex,
			CurrentIndex:       targetStreamIndex,
			Data:               payload,
			OriginalSequenceId: currentDataSeqId,
		})
		multiplexer.QuickRetryQueueMu.Unlock()
		return
	}

	log.Print("write on mx seq id ", currentDataSeqId)
	err := targetStream.WriteData(encodedPayload)
	if err != nil {
		log.Print("error: failed to write: queueing to quick retry queue: ", err)
		multiplexer.QuickRetryQueueMu.Lock()
		multiplexer.QuickRetryQueue = append(multiplexer.QuickRetryQueue, &ToRetry{
			FirstIndex:         targetStreamIndex,
			CurrentIndex:       targetStreamIndex,
			Data:               payload,
			OriginalSequenceId: currentDataSeqId,
		})
		multiplexer.QuickRetryQueueMu.Unlock()
	} else {
		multiplexer.UnacknowledgedPacketMu.Lock()
		log.Print("write current data seq id ", currentDataSeqId, " to be acknowledged")
		multiplexer.UnacknowledgedPackets[currentDataSeqId] = &UnacknowledgedPacket{
			WebsocketIndex: targetStreamIndex,
			Payload:        payload,
		}
		multiplexer.UnacknowledgedPacketMu.Unlock()
	}
}

func (multiplexer *WebsocketMultiplexer) SendSignalRawOnAny(payload []byte, existingSeq *uint32) {
	currentCounter := multiplexer.SignalRoundRobinCounter.Load()
	multiplexer.SignalRoundRobinCounter.Add(1)

	multiplexer.SendDataOnAnyWithIndex(currentCounter, payload, existingSeq)
}

func (multiplexer *WebsocketMultiplexer) SendDataRawOnAny(payload []byte, existingSeq *uint32) {
	currentCounter := multiplexer.DataStreamRoundRobinCounter.Load()
	multiplexer.DataStreamRoundRobinCounter.Add(1)

	multiplexer.SendDataOnAnyWithIndex(currentCounter, payload, existingSeq)
}

func (multiplexer *WebsocketMultiplexer) SendSignal(messageType MessageType, data []byte) {
	// encode pckt
	seqIdBuf := make([]byte, 4)
	seqIdCurrent := multiplexer.SignalSequenceId.Add(1) - 1
	binary.BigEndian.PutUint32(seqIdBuf, seqIdCurrent)

	payloadPacket := append(seqIdBuf, data...)

	encodedPacket := multiplexer.EncodePacket(messageType, payloadPacket)
	multiplexer.SendSignalRawOnAny(encodedPacket, nil)
}

func (multiplexer *WebsocketMultiplexer) SendSignalOnWebsocket(wsStream *WSStream, messageType MessageType, data []byte) error {
	// encode pckt
	seqIdBuf := make([]byte, 4)
	seqIdCurrent := multiplexer.SignalSequenceId.Add(1) - 1
	binary.BigEndian.PutUint32(seqIdBuf, seqIdCurrent)

	payloadPacket := append(seqIdBuf, data...)

	encodedPacket := multiplexer.EncodePacket(messageType, payloadPacket)
	currentDataSeqId := multiplexer.MultiplexerSequenceID.Add(1) - 1
	log.Print("in signal on wss, incremented mx seq id by 1 to: ", currentDataSeqId)
	encodedPayload := multiplexer.EncodePayload(encodedPacket, currentDataSeqId)
	return wsStream.WriteData(encodedPayload)

}

func (multiplexer *WebsocketMultiplexer) SendData(messageType MessageType, data []byte) {
	encodedPacket := multiplexer.EncodePacket(messageType, data)
	multiplexer.SendDataRawOnAny(encodedPacket, nil)
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
	log.Print("set stream to active: ", stream.Index)
	multiplexer.ActiveStreamIndexes = append(multiplexer.ActiveStreamIndexes, stream.Index)
	multiplexer.ActiveStreamIndexesMu.Unlock()

	multiplexer.DoQuickRetry()
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
	log.Print("debug: sending ACK for packet sequence ", seqId)

	acknowledgedSeqIdBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(acknowledgedSeqIdBuf, seqId)
	multiplexer.SendSignal(MessageTypeAcknowledged, acknowledgedSeqIdBuf)
}

func (multiplexer *WebsocketMultiplexer) DecodePacket(decryptedData []byte) *DecodedPacket {
	// 4 multiplexer seq id 1 msg type 4 msg size ...payload
	// in the case of signal packets, there will be an additional 4 bytes for signal sequencer id

	multiplexer.StreamInLog(decryptedData, "RECV")

	messageMpSeqIdBuf := decryptedData[:4]
	messageType := decryptedData[4]
	messageSizeBuf := decryptedData[5:9]
	messageSizeInt := binary.BigEndian.Uint32(messageSizeBuf)
	mpSeqId := binary.BigEndian.Uint32(messageMpSeqIdBuf)

	if int(messageSizeInt) < 0 || int(messageSizeInt) > len(decryptedData)-9 {
		log.Print("error: failed to process packet: message size out of range")
		return &DecodedPacket{
			MessageType: messageType,
			Payload:     []byte{},
			SequenceId:  mpSeqId,
		}
	}

	messagePayload := decryptedData[9 : 9+messageSizeInt]

	return &DecodedPacket{
		MessageType: messageType,
		Payload:     messagePayload,
		SequenceId:  mpSeqId,
	}
}

func (multiplexer *WebsocketMultiplexer) DecodedSignalPacket(predecodedPacket *DecodedPacket) *SignalDecodedPacket {
	// decodes the additional 4 bytes for SIGNAL

	messageSignalSequenceIdBuf := predecodedPacket.Payload[:4]
	messagePayload := predecodedPacket.Payload[4:]

	signalSeqId := binary.BigEndian.Uint32(messageSignalSequenceIdBuf)

	return &SignalDecodedPacket{
		MessageType:      predecodedPacket.MessageType,
		Payload:          messagePayload,
		SequenceId:       predecodedPacket.SequenceId,
		SignalSequenceId: signalSeqId,
	}
}

func (multiplexer *WebsocketMultiplexer) Disconnect() {
	multiplexer.SessionEnded.Store(true)

	for _, connection := range multiplexer.Streams {
		connection.Close()
	}
}

func (multiplexer *WebsocketMultiplexer) ReorderSignalPackets(conn *WSStream, newPacket *DecodedPacket, processFunc func(signalpacket *SignalDecodedPacket, conn *WSStream) PacketProcessingResult) {
	signalpacket := multiplexer.DecodedSignalPacket(newPacket)

	multiplexer.SignalUnorderedMu.Lock()
	defer multiplexer.SignalUnorderedMu.Unlock()

	expected := multiplexer.SignalExpectedSeqId.Load()

	if signalpacket.SignalSequenceId < expected {
		log.Print("warn: packet arrived too late. expected: ", expected, " got: ", signalpacket.SignalSequenceId)
		return
	}

	if signalpacket.SignalSequenceId > expected+500 {
		log.Print("warn: packet arrived way too early! expected: ", expected, " current: ", signalpacket.SignalSequenceId)
		return
	}

	log.Print("added packet seq id: ", signalpacket.SignalSequenceId)

	multiplexer.SignalUnordered[signalpacket.SignalSequenceId] = signalpacket

	for {
		currentSequenceId := multiplexer.SignalExpectedSeqId.Load()
		currentSignalPacket, exists := multiplexer.SignalUnordered[currentSequenceId]
		if !exists {
			log.Print("end of reorder chunk. expected next seq id is: ", currentSequenceId)
			return
		}

		log.Print("seq id reorder: ", currentSequenceId, " payload is: ", currentSignalPacket.Payload)
		result := processFunc(currentSignalPacket, conn)
		if result == PacketProcessingDisconnect {
			log.Print("disconnecting connection, as requested by signal processor")
			multiplexer.Disconnect()
		}
		delete(multiplexer.SignalUnordered, currentSequenceId)
		multiplexer.SignalExpectedSeqId.Add(1)
	}

}

func (multiplexer *WebsocketMultiplexer) DoQuickRetry() {
	multiplexer.QueuedForResendMu.Lock()
	defer multiplexer.QueuedForResendMu.Unlock()

	for i, pckt := range multiplexer.QueuedForResend {
		log.Print("attempting to resend packet: ", i)
		multiplexer.SendDataRawOnAny(pckt, nil)
		// We shouldn't need any existing signal
		// since the MX sequencer ID should not have been incremented
	}

	multiplexer.QueuedForResend = multiplexer.QueuedForResend[:0]
}

func (multiplexer *WebsocketMultiplexer) DoQuickResendLoop() {
	ticker := time.NewTicker(250 * time.Millisecond)

	for range ticker.C {

		multiplexer.QuickRetryQueueMu.Lock()

		for i, pckt := range multiplexer.QuickRetryQueue {
			log.Print("attempt to quick retry resend packet: ", i)
			multiplexer.SendDataRawOnAny(pckt.Data, &pckt.OriginalSequenceId)
		}

		multiplexer.QuickRetryQueue = multiplexer.QuickRetryQueue[:0]
		multiplexer.QuickRetryQueueMu.Unlock()
	}
}

func (multiplexer *WebsocketMultiplexer) HandleSocketDied(streamIndex uint32) int {
	packetsToBeRetransmitted := 0

	multiplexer.UnacknowledgedPacketMu.Lock()
	defer multiplexer.UnacknowledgedPacketMu.Unlock()

	for seqId, packet := range multiplexer.UnacknowledgedPackets {
		if packet.WebsocketIndex == streamIndex {
			packetsToBeRetransmitted++

			multiplexer.QuickRetryQueueMu.Lock()
			multiplexer.QuickRetryQueue = append(multiplexer.QuickRetryQueue, &ToRetry{
				FirstIndex:         packet.WebsocketIndex,
				CurrentIndex:       packet.WebsocketIndex,
				Data:               packet.Payload,
				OriginalSequenceId: seqId,
			})
			multiplexer.QuickRetryQueueMu.Unlock()
			delete(multiplexer.UnacknowledgedPackets, seqId)
		}
	}

	return packetsToBeRetransmitted
}

func (multiplexer *WebsocketMultiplexer) Initialize() {
	log.Print("initializing websocket multiplexer")
	go multiplexer.DoQuickResendLoop()
}

func (multiplexer *WebsocketMultiplexer) SetSecretOnAll() {
	multiplexer.StreamsMu.Lock()
	defer multiplexer.StreamsMu.Unlock()

	for _, conn := range multiplexer.Streams {
		conn.SetSharedSecret(multiplexer.SharedSecret)
	}
}

func (multiplexer *WebsocketMultiplexer) SetReadyToAll() {
	multiplexer.StreamsMu.Lock()
	defer multiplexer.StreamsMu.Unlock()

	for _, conn := range multiplexer.Streams {
		conn.SetReady(true)
	}
}
