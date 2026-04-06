package main

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/CariLT01/net-tunnel-common/shared"
	"github.com/gorilla/websocket"
)

type SessionCreationResponse struct {
	Ok            bool    `json:"ok"`
	Message       string  `json:"message"`
	SessionId     *int    `json:"sessionId"`
	IdentityToken *string `json:"identityToken"`
}

func (app *ConnectionHandler) connectToWebsocket() (*shared.WSStream, error) {
	u := url.URL{Scheme: app.config.config.WebsocketScheme, Host: app.config.config.VpnServer, Path: "/stream"}
	q := u.Query()
	q.Set("sessionId", strconv.Itoa(app.sessionId))

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+app.identityToken)

	u.RawQuery = q.Encode()
	c, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		log.Print("Failed to dial: ", err)
		return nil, fmt.Errorf("Failed to dial target: %s", err)
	}

	connectionObj := app.multiplexer.NewWebsocketStream(c)

	app.multiplexer.AddWebsocketStream(connectionObj)

	return connectionObj, nil
}

func (app *ConnectionHandler) onSocketDied(conn *shared.WSStream) {

	packetsToBeRetransmitted := app.multiplexer.HandleSocketDied(conn.Index)

	log.Print("count packets to be retransmitted: ", packetsToBeRetransmitted)
	log.Print("attempting to reconnect")
	app.CreateWebSocket()
}

func (app *ConnectionHandler) DeleteWebsocket(conn *shared.WSStream) {
	app.wssConnectionsMutex.Lock()
	defer app.wssConnectionsMutex.Unlock()
	app.multiplexer.DeleteWebsocketStream(conn)
}

func (app *ConnectionHandler) HandleNetworkData(decodedPacket *shared.DecodedPacket) {
	if decodedPacket.MessageType != shared.MessageTypeNetwork {
		log.Print("error: not a network packet")
		return
	}

	//log.Print("originally received pre-decoded packet: ", base64.StdEncoding.EncodeToString(decodedPacket.Payload))

	clientId := decodedPacket.Payload[0]
	messagePayload := decodedPacket.Payload[1:]

	//log.Print("message payload: ", base64.StdEncoding.EncodeToString(messagePayload))

	app.localConnectionsMutex.RLock()
	localConnection, exists := app.localConnections[int(clientId)]
	app.localConnectionsMutex.RUnlock()
	if !exists {
		log.Print("error: failed to foward data: stream id does not exist")
		return
	}

	seqId, packetPayload := localConnection.DecodePacketPayload(messagePayload)
	localConnection.OnPacketReceived(packetPayload, seqId)

}

func (app *ConnectionHandler) HandleWebsocketMessage(signalpacket *shared.SignalDecodedPacket) shared.PacketProcessingResult {
	if signalpacket.MessageType == shared.MessageTypeSignature { // means client ready

		if !(app.multiplexer.ProtocolCompletion.KyberHandshakeReceived) {
			log.Print("error: cannot verify signature without kyber handshake")
			log.Print("cannot verify signature without kyber handshake")

			return shared.PacketProcessingDisconnect
		}

		log.Print("Connection reported established, need to verify key match")
		log.Printf("handshake transcript signature (EdDSA): %x\n", signalpacket.Payload)
		log.Print("handshake transcript: ", app.multiplexer.HandshakeTranscript)
		valid := VerifySignature(CERTIFICATE_PUBLIC_KEY, app.multiplexer.HandshakeTranscript, signalpacket.Payload)
		if !valid {
			log.Print("--- MAN IN THE MIDDLE TAMPERING DETECTED ---")
			log.Fatal("Ending all connections immediately")
		}
		log.Print("valid signature detected, trusting server")

		// we need to verify key confirmation and transcript
		transcriptHash := sha256.Sum256(app.multiplexer.HandshakeTranscript)
		prk, err := hkdf.Extract(sha256.New, app.multiplexer.SharedSecret, transcriptHash[:])
		if err != nil {
			log.Print("error: hkdf failed to extract: ", err)
			return shared.PacketProcessingDisconnect
		}
		confirmKey, err := hkdf.Expand(sha256.New, prk, "confirm", 32)
		if err != nil {
			log.Print("error: hkdf failed to expand: ", err)
			return shared.PacketProcessingDisconnect
		}

		log.Print("Derived key: ", len(confirmKey), " bytes")

		mac := hmac.New(sha256.New, confirmKey)
		mac.Write(app.multiplexer.HandshakeTranscript)
		mac.Write([]byte("client"))
		clientConfirm := mac.Sum(nil)

		clientMac := clientConfirm

		app.multiplexer.SendSignal(shared.MessageTypeReady, clientMac)

		log.Print("sent confirmation to server: ", len(clientMac), " bytes")

		app.multiplexer.ProtocolCompletion.SignatureReceived = true

	} else if signalpacket.MessageType == shared.MessageTypeStreamDisconnect { // server requested disconnect

		clientId := signalpacket.Payload[0]

		app.localConnectionsMutex.Lock()
		localConnection, exists := app.localConnections[int(clientId)]

		if !exists {
			log.Print("ignoring disconnect: client ID ", clientId, " not found")
			app.localConnectionsMutex.Unlock()
			return shared.PacketProcessingSkipped
		}

		localConnection.Connection.Close()
		log.Print("closed connection ", clientId, " as requested by server")
		delete(app.localConnections, int(clientId))
		app.localConnectionsMutex.Unlock()

		app.clientConnectionIDsRWMutex.Lock()
		_, exists = app.clientConnectionIDs[int(clientId)]
		if !exists {
			log.Print("does not exist in clientid")
			app.clientConnectionIDsRWMutex.Unlock()
			return shared.PacketProcessingSkipped
		}
		delete(app.clientConnectionIDs, int(clientId))
		app.clientConnectionIDsRWMutex.Unlock()
		log.Print("deleted client id entry: ", clientId)
	} else if signalpacket.MessageType == shared.MessageTypeHandshake { // means handshake data
		log.Print("received handshake")
		app.multiplexer.HandshakeTranscript = append(app.multiplexer.HandshakeTranscript, signalpacket.Payload...)
		publicKeyBin := signalpacket.Payload
		publicKey, err := app.multiplexer.Scheme.UnmarshalBinaryPublicKey(publicKeyBin)
		if err != nil {
			log.Print("error: handshake failed: failed to unmarshal key: ", err)
			return shared.PacketProcessingDisconnect
		}

		ciphertext, sharedSecret, err := app.multiplexer.Scheme.Encapsulate(publicKey)
		if err != nil {
			log.Print("error: handshake failed: failed to encapsulate key: ", err)
			return shared.PacketProcessingDisconnect
		}

		app.multiplexer.SharedSecret = sharedSecret
		app.multiplexer.SetSecretOnAll()

		app.multiplexer.SendSignal(shared.MessageTypeHandshake, ciphertext)
		app.multiplexer.HandshakeTranscript = append(app.multiplexer.HandshakeTranscript, ciphertext...)

		log.Print("wrote ciphertext")

		app.multiplexer.ProtocolCompletion.KyberHandshakeReceived = true

	} else if signalpacket.MessageType == shared.MessageTypeReady {

		if !(app.multiplexer.ProtocolCompletion.KyberHandshakeReceived && app.multiplexer.ProtocolCompletion.SignatureReceived) {
			log.Print("error: cannot confirm key before kyber handshake and signature validation")
			return shared.PacketProcessingDisconnect
		}

		serverMac := signalpacket.Payload

		// derive key again
		transcriptHash := sha256.Sum256(app.multiplexer.HandshakeTranscript)
		prk, err := hkdf.Extract(sha256.New, app.multiplexer.SharedSecret, transcriptHash[:])
		if err != nil {
			log.Print("error: hkdf failed to extract: ", err)
		}
		confirmKey, err := hkdf.Expand(sha256.New, prk, "confirm", 32)
		if err != nil {
			log.Print("error: hkdf failed to expand: ", err)
		}

		log.Print("Derived key: ", len(confirmKey), " bytes")

		// write expected server mac
		mac := hmac.New(sha256.New, confirmKey)
		mac.Write(app.multiplexer.HandshakeTranscript)
		mac.Write([]byte("server"))

		if !hmac.Equal(serverMac, mac.Sum(nil)) {
			log.Print("error: authenticity verification failed: HMAC mismatch, ending connection")
			return shared.PacketProcessingDisconnect
		} else {
			app.multiplexer.ProtocolCompletion.KeyConfirmationReceived = true
			log.Print("passed key confirmation check")

			if !(app.multiplexer.ProtocolCompletion.KeyConfirmationReceived == true && app.multiplexer.ProtocolCompletion.KyberHandshakeReceived == true && app.multiplexer.ProtocolCompletion.SignatureReceived == true) {
				log.Print("error: invalid handshake. skipped one or more steps")
				return shared.PacketProcessingDisconnect
			} else {
				log.Print("protocol handshake complete")
			}

			app.multiplexer.Ready.Store(true)
			app.multiplexer.SetReadyToAll()
			app.multiplexer.SetSecretOnAll()

			log.Print("connection is ready")

			log.Print("marked handshake succeeded")

		}
	} else if signalpacket.MessageType == shared.MessageTypeAcknowledged {
		app.multiplexer.UnacknowledgedPacketMu.Lock()
		defer app.multiplexer.UnacknowledgedPacketMu.Unlock()

		packetSeqIdBuf := signalpacket.Payload[:4]
		packetSeqIdInt := binary.BigEndian.Uint32(packetSeqIdBuf)

		_, exists := app.multiplexer.UnacknowledgedPackets[packetSeqIdInt]
		if !exists {
			log.Print("acknowledged seq id not found: ", packetSeqIdInt)
			return shared.PacketProcessingSkipped
		}

		delete(app.multiplexer.UnacknowledgedPackets, packetSeqIdInt)
		log.Print("deleted seq id from unacknowledged packet: ", packetSeqIdInt)

	} else {
		log.Print("error: unrecognized message type: ", signalpacket.MessageType)
		return shared.PacketProcessingSkipped
	}
	return shared.PacketProcessingOK
}

func (app *ConnectionHandler) HandleWebsocketRead(conn *shared.WSStream) {
	defer conn.GetConnection().Close()
	defer app.onSocketDied(conn)
	defer app.DeleteWebsocket(conn)

	app.multiplexer.SetActive(conn)

	if !app.multiplexer.Ready.Load() {
		log.Print("not ready")
		if app.multiplexer.IsDoingHandshake.Load() == false {
			// first send message 4, which is clientHello
			nonce, err := GenerateSecureSecret()
			if err != nil {
				log.Print("error: failed to generate nonce")
				return
			}
			app.multiplexer.SendSignal(shared.MessageTypeClientHello, nonce)
			app.multiplexer.HandshakeTranscript = append(app.multiplexer.HandshakeTranscript, nonce...)
			log.Print("sent client hello nonce")

			app.multiplexer.IsDoingHandshake.Store(true)
		} else {
			log.Print("already doing handshake")
		}

	} else {
		conn.SetReady(true)
		app.multiplexer.SetSecretOnAll()
	}

	// step-by-step protocol

	for {
		_, rawMessageEncrypted, err := conn.GetConnection().ReadMessage()
		if err != nil {
			log.Print("Proxy Websocket Disconnected")
			conn.SetReady(false)
			// get index
			app.multiplexer.SetInactive(conn)
			app.multiplexer.DeleteWebsocketStream(conn)
			break
		}
		rawMessage, err := conn.DecodeReadData(rawMessageEncrypted)
		if err != nil {
			log.Print("Failed to decrypt message: ", err)
			continue
		}

		decodedPacket := app.multiplexer.DecodePacket(rawMessage)
		// don't ACK the ACk
		if decodedPacket.MessageType != shared.MessageTypeAcknowledged {
			if decodedPacket.MessageType != shared.MessageTypeReady {
				// if it is ready, do it AFTER processing
				app.multiplexer.SendAcknowledged(decodedPacket.SequenceId)
			}

		}

		if decodedPacket.MessageType == shared.MessageTypeNetwork {
			app.HandleNetworkData(decodedPacket)
		} else if decodedPacket.MessageType == shared.MessageTypeReady {
			app.multiplexer.ReorderSignalPackets(decodedPacket, app.HandleWebsocketMessage)
		} else if decodedPacket.MessageType == shared.MessageTypeAcknowledged {
			app.multiplexer.ReorderSignalPackets(decodedPacket, app.HandleWebsocketMessage)
		} else if decodedPacket.MessageType == shared.MessageTypeClientHello {
			app.multiplexer.ReorderSignalPackets(decodedPacket, app.HandleWebsocketMessage)
		} else if decodedPacket.MessageType == shared.MessageTypeHandshake {
			app.multiplexer.ReorderSignalPackets(decodedPacket, app.HandleWebsocketMessage)
		} else if decodedPacket.MessageType == shared.MessageTypeTCPAcknowledged {
			app.multiplexer.ReorderSignalPackets(decodedPacket, app.HandleWebsocketMessage)
		} else if decodedPacket.MessageType == shared.MessageTypeSignalAcknowledged {
			app.multiplexer.ReorderSignalPackets(decodedPacket, app.HandleWebsocketMessage)
		} else if decodedPacket.MessageType == shared.MessageTypeSignature {
			app.multiplexer.ReorderSignalPackets(decodedPacket, app.HandleWebsocketMessage)
		} else if decodedPacket.MessageType == shared.MessageTypeAcknowledged {
			app.multiplexer.ReorderSignalPackets(decodedPacket, app.HandleWebsocketMessage)
		}

		if decodedPacket.MessageType == shared.MessageTypeReady {
			// If it's a ready packet, do it AFTER
			app.multiplexer.SendAcknowledged(decodedPacket.SequenceId)
		}

	}
}

func (app *ConnectionHandler) CreateWebSocket() error {
	socketObj, err := app.connectToWebsocket()
	if err != nil {
		return fmt.Errorf("Failed to create WebSocket: %s", err)
	}
	go app.HandleWebsocketRead(socketObj)
	return nil
}

func (app *ConnectionHandler) CreateSession() {

	// solve pow

	sessionManager := SessionManager{}
	app.keys = sessionManager.FetchPublicKey(app.config)
	challengeToken, nonce := app.powSolver.GetChallengeAndSolve(app.config, app.keys)
	log.Print("solution: ", nonce)

	u := url.URL{Scheme: app.config.config.HttpScheme, Host: app.config.config.VpnServer, Path: "/session/create"}
	q := u.Query()
	q.Set("challengeToken", challengeToken)
	q.Set("solution", strconv.FormatInt(nonce, 10))
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("failed to read body: ", err)
	}

	// log.Print("body: " + string(body))

	var r SessionCreationResponse
	json.Unmarshal(body, &r)

	if r.Ok == false {
		log.Fatal("failed to create session: ", r.Message)
	}
	if r.SessionId == nil {
		log.Fatal("failed to create session. server returned ok=true but data=nil")
	}
	if r.IdentityToken == nil {
		log.Fatal("no identity token returned")
	}

	identityToken := *r.IdentityToken

	if !VerifyIdentityToken(identityToken, *r.SessionId, app.keys.identityKey) {
		log.Fatal("identity token is not valid")
	}

	app.sessionId = *r.SessionId
	app.identityToken = *r.IdentityToken
	log.Print("identity token (len): ", len(app.identityToken))
	log.Print("created session id: ", app.sessionId)
}

func (app *ConnectionHandler) Initialize() {

	log.Print("loading config")
	// Load config, save it to ensure the file exists
	app.config.LoadConfig()
	app.config.SaveConfig()

	app.CreateSession()

	streamsFailed := 0
	streamsToCreate := 2

	for i := 0; i < streamsToCreate; i++ {
		err := app.CreateWebSocket()
		if err != nil {
			log.Print("error: Failed to create stream: ", err)
			streamsFailed++
			continue
		}
		log.Print("Connection #", i, " created")
	}

	if streamsFailed >= streamsToCreate {
		log.Fatal("fatal: cannot connect: no connections can be established")
	}

	go app.MultiplexingScalingLoop()

	app.multiplexer.Initialize()
}

func (app *ConnectionHandler) SocketWriteMessageRaw(socket *ProxyWebsocketConnection, message []byte) error {
	socket.writeMutex.Lock()
	// log.Print("forwarding ", len(message), " to websocket")
	err := socket.connection.WriteMessage(websocket.BinaryMessage, message)
	socket.writeMutex.Unlock()
	return err
}

func (app *ConnectionHandler) reserveClientID() int {
	app.clientConnectionIDsRWMutex.Lock()
	defer app.clientConnectionIDsRWMutex.Unlock()

	if len(app.clientConnectionIDs) >= 255 {
		log.Print("error: unable to reserve client id. list is saturated and cannot hold anymore connections")
		return -1
	}

	attemptsCount := 0

	for {
		if attemptsCount >= 5000 {
			log.Print("error: could not reserve client id in reasonable amount of time")
			return -1
		}
		clientId := rand.IntN(255)

		_, exists := app.clientConnectionIDs[clientId]
		if !exists {
			app.clientConnectionIDs[clientId] = struct{}{}
			log.Print("found client id ", clientId, " after ", attemptsCount, " attempts")
			return clientId
		} else {
			attemptsCount++
		}

	}
}

func (app *ConnectionHandler) GetConnectedCount() int {
	app.localConnectionsMutex.RLock()
	defer app.localConnectionsMutex.RUnlock()
	c := 0
	for range app.localConnections {
		c++
	}
	return c
}

func (app *ConnectionHandler) FindChosenWebsocketVictim() *shared.WSStream {
	app.multiplexer.StreamsMu.RLock()
	defer app.multiplexer.StreamsMu.RUnlock()
	return app.multiplexer.Streams[0] // With round robin, dropping any is fine

}

func (app *ConnectionHandler) MultiplexingScalingLoop() {
	ticker := time.NewTicker(time.Second)

	for range ticker.C {
		// calculate average connections per socket
		connectionsPerSocketSum := app.GetConnectedCount()
		connectionsPerSocketAvg := (float32(connectionsPerSocketSum) / float32(len(app.multiplexer.ActiveStreamIndexes)))

		log.Print("scaling: connections per socket: ", connectionsPerSocketAvg)

		// levels
		// < 2 --> drop
		// > 5 --> add

		if connectionsPerSocketAvg < 6 {
			log.Print("attempting to downscale")
			// don't downscale to less than 2
			if len(app.multiplexer.ActiveStreamIndexes) <= 2 {
				log.Print("not downscaling, reached minimum wss connection count")
				continue
			}
			// drop the least worthy websocket
			leastWorthySocket := app.FindChosenWebsocketVictim()
			if leastWorthySocket == nil {
				log.Print("error: failed to scale down: no socket to drop")
				continue
			}

			log.Print("set intentionally disconnected = true")
			leastWorthySocket.SetIntentionallyDisconnected(true)
			leastWorthySocket.Close()
		} else if connectionsPerSocketAvg > 12 {
			log.Print("attempting to upscale")

			if len(app.multiplexer.Streams) >= NUMBER_OF_CONNECTIONS {
				log.Print("not upscaling, reached maximum wss connection count")
			}

			log.Print("creating websocket")
			app.CreateWebSocket()
		} else {
			log.Print("scaling ok -- multiplex: ", len(app.multiplexer.Streams), " /  connections per socket avg: ", connectionsPerSocketAvg, " / sum: ", connectionsPerSocketSum)
		}
	}
}

func (app *ConnectionHandler) GetActiveConnections() []int {
	return app.activeConnectionIndexes
}

func (app *ConnectionHandler) HandleNewConnection(conn net.Conn) {

	log.Print("new tcp connection")

	clientId := app.reserveClientID()
	log.Print("got client: ", clientId)
	if clientId == -1 {
		log.Print("error: connection failed. failed to reserve client id")
		conn.Close()
		return
	}

	app.localConnectionsMutex.Lock()
	localConnection := shared.NewTCPStream(conn)
	app.localConnections[clientId] = localConnection
	app.localConnectionsMutex.Unlock()

	log.Print("reserved client id: ", clientId)

	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Print("detected tcp socket closed. error: ", err)
			if clientId != -1 {
				log.Print("writing disconnect to server")
				//writeErr := app.SocketWriteMessage(wsSocket, []byte{2, byte(clientId)})
				app.multiplexer.SendSignal(shared.MessageTypeStreamDisconnect, []byte{byte(clientId)})

				// make sure to unreserve it
				app.clientConnectionIDsRWMutex.Lock()
				delete(app.clientConnectionIDs, clientId)
				app.clientConnectionIDsRWMutex.Unlock()

				// make sure to delete the connection
				app.localConnectionsMutex.Lock()
				log.Print("delete from map: ", clientId)
				delete(app.localConnections, clientId)
				app.localConnectionsMutex.Unlock()

			}
			return
		}

		// sequence id

		encodedPacket := localConnection.EncodePacketPayload(byte(clientId), buf[:n])
		//log.Print("sending from TCP: ", base64.StdEncoding.EncodeToString(encodedPacket))
		app.multiplexer.SendData(shared.MessageTypeNetwork, encodedPacket)

		// log.Print("received ", n, " bytes from TCP")

		// write

		//
		// log.Printf("sent message sum sha256: %x\n", sha256.Sum256(buf[:n]))
		// log.Print("Message sent to server: ", base64.StdEncoding.EncodeToString(buf[:n]))

	}
}
