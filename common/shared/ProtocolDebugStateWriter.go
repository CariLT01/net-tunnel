package shared

import (
	"encoding/json"
	"log"
	"os"
)

/* JSON structs */
type StateStruct struct {
	ReorderingPacketsSignal []uint32 `json:"reorderingPacketsSignal"`
	// waiting for...
	WaitingForSignal uint32 `json:"waitingForSignalSeq"`

	// to be acknowledged packets on send
	PendingPacketsMx []uint32 `json:"pendingPacketsMxSeq"`

	// send multiplexer ID
	SendSignalSeq uint32 `json:"sendSignalSeq"`
	SendMxSeq     uint32 `json:"sendMxSeq"`
}

type ProtocolDebugStateWriter struct {
	file *os.File
}

func (writer *ProtocolDebugStateWriter) Initialize(filename string) {

	// open the file
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Unable to open file '%s': %s", filename, err)
	}

	writer.file = file
}

/* serialize to the required format */
func (writer *ProtocolDebugStateWriter) GetToBeReorderedSignal(multiplexer *WebsocketMultiplexer) []uint32 {
	packets := make([]uint32, 0)

	for packetId := range multiplexer.SignalUnordered {
		packets = append(packets, packetId)
	}

	return packets
}

/*
returns the pending packets for multiplexer
packets that are waiting for acknowledgement by
the recipient
*/
func (writer *ProtocolDebugStateWriter) GetPendingMxPackets(multiplexer *WebsocketMultiplexer) []uint32 {

	packets := make([]uint32, 0)

	for packetId := range multiplexer.UnacknowledgedPackets {
		packets = append(packets, packetId)
	}

	return packets
}

/* writes current state for debugging */
func (writer *ProtocolDebugStateWriter) WriteDebugState(multiplexer *WebsocketMultiplexer) {

	log.Print("debug: writing to state logs")

	stateData := StateStruct{
		ReorderingPacketsSignal: writer.GetToBeReorderedSignal(multiplexer),
		WaitingForSignal:        multiplexer.SignalExpectedSeqId.Load(),
		PendingPacketsMx:        writer.GetPendingMxPackets(multiplexer),
		SendSignalSeq:           multiplexer.SignalSequenceId.Load(),
		SendMxSeq:               multiplexer.MultiplexerSequenceID.Load(),
	}

	jsonData, err := json.Marshal(stateData)

	if err != nil {
		log.Printf("error: failed to encode into json: %s", err)
		return
	}

	// append a new line for parsing
	processedJsonData := append(jsonData, '\n')

	_, err = writer.file.Write(processedJsonData)
	if err != nil {
		log.Printf("error: failed to write debug state into file: %s", err)
		return
	}

	err = writer.file.Sync()
	if err != nil {
		log.Printf("error: failed to sync contents to disk: %s", err)
	}
}

/* Constructor */
func NewProtocolDebugStateWriter() *ProtocolDebugStateWriter {
	return &ProtocolDebugStateWriter{}
}
