package shared

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

type TCPStream struct {
	Connection net.Conn

	// Reordering
	sendSequenceId     atomic.Uint32
	expectedSequenceId atomic.Uint32
	queuedPackets      map[uint32][]byte
	queuedPacketsMu    sync.RWMutex

	// Acknowledgement and retransmition
	toBeAcknowledgedPackets   map[uint32][]byte
	toBeAcknowledgedPacketsMu sync.RWMutex
}

func (stream *TCPStream) OnPacketReceived(packet []byte, sequenceId uint32) {
	if sequenceId < stream.expectedSequenceId.Load() {
		log.Print("another packet with the same sequence id arrived before!")
		return
	}

	if sequenceId-stream.expectedSequenceId.Load() > 500 {
		log.Print("packet arrived way too late!")
		return
	}

	stream.queuedPacketsMu.Lock()
	stream.queuedPackets[sequenceId] = packet
	defer stream.queuedPacketsMu.Unlock()

	for {
		expectedSequenceIdCurrent := stream.expectedSequenceId.Load()
		currentMessage, exists := stream.queuedPackets[expectedSequenceIdCurrent]
		if !exists {
			log.Print("found end of reordering stream")
			break
		}

		
		stream.Connection.Write(currentMessage)
		delete(stream.queuedPackets, expectedSequenceIdCurrent)
		stream.expectedSequenceId.Add(1)
	}

}

func (stream *TCPStream) EncodePacketPayload(clientId byte, packetData []byte) []byte {
	currentSeqId := stream.sendSequenceId.Load()
	stream.sendSequenceId.Add(1)

	seqIdBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(seqIdBuf, uint32(currentSeqId))

	payload := append(append([]byte{clientId}, seqIdBuf...), packetData...)
	return payload
}

func (stream *TCPStream) DecodePacketPayload(rawData []byte) (uint32, []byte) {
	seqId := rawData[:4]
	packetData := rawData[5:]

	sequenceId := binary.BigEndian.Uint32(seqId)

	return sequenceId, packetData
}

func NewTCPStream(connection net.Conn) *TCPStream {
	return &TCPStream{
		Connection: connection,
		sendSequenceId: atomic.Uint32{},
		expectedSequenceId: atomic.Uint32{},
		queuedPackets: make(map[uint32][]byte),
		queuedPacketsMu: sync.RWMutex{},
		toBeAcknowledgedPackets: make(map[uint32][]byte),
		toBeAcknowledgedPacketsMu: sync.RWMutex{},
	
	}
}
