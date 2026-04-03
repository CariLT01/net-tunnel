package shared

type PacketProcessingResult = byte

const (
	PacketProcessingOK         PacketProcessingResult = 0x00 // The packet was processed successfully without issues
	PacketProcessingSkipped    PacketProcessingResult = 0x01 // The packet experienced an issue during processing and was skipped
	PacketProcessingDisconnect PacketProcessingResult = 0x02 // The packet experienced a severe issue and the underlying connection must be disconnected
)
