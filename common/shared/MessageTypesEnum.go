package shared

type MessageType = byte

const (
	MessageTypeNetwork            MessageType = 0x00 // Network packet, from tunneling
	MessageTypeSignature          MessageType = 0x01 // Signature packet
	MessageTypeStreamDisconnect   MessageType = 0x02 // Server requested disconnect
	MessageTypeHandshake          MessageType = 0x03 // Encryption Handshake
	MessageTypeClientHello        MessageType = 0x04 // Client Hello
	MessageTypeReady              MessageType = 0x06 // READY packet, includes HMAC key confirmation check
	MessageTypeTCPAcknowledged    MessageType = 0x07 // TCP packet is acknowledged
	MessageTypeSignalAcknowledged MessageType = 0x08 // Signal packet is acknowledged
	MessageTypeAcknowledged       MessageType = 0x09 // Packet is acknowledged
	MessageTypePing               MessageType = 0x0A // Latency check PING
	MessageTypePong               MessageType = 0x0B // Latency check PONG
)
