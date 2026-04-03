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
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/gorilla/websocket"
)

type SessionCreationResponse struct {
	Ok            bool    `json:"ok"`
	Message       string  `json:"message"`
	SessionId     *int    `json:"sessionId"`
	IdentityToken *string `json:"identityToken"`
}

func (app *ConnectionHandler) connectToWebsocket() (*ProxyWebsocketConnection, error) {
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

	connectionObj := &ProxyWebsocketConnection{
		ready:                     atomic.Bool{},
		handshakeSucceeded:        atomic.Bool{},
		intentionallyDisconnected: atomic.Bool{},
		connection:                c,
		connectedCount:            atomic.Int64{},
		writeMutex:                sync.Mutex{},
	}

	app.wssConnectionsMutex.Lock()
	app.wssConnections = append(app.wssConnections, connectionObj)
	app.wssConnectionsMutex.Unlock()

	return connectionObj, nil
}

func (app *ConnectionHandler) onSocketDied(conn *ProxyWebsocketConnection) {
	if conn.handshakeSucceeded.Load() == true && conn.intentionallyDisconnected.Load() == false {
		// only if it was actually ready
		// don't want to be stuck in a never-ending loop of unsuccessful sockets
		log.Print("attempting to reconnect")
		app.CreateWebSocket()
	} else {
		log.Print("not attempting to reconnect. handshake failed or intentionally disconnected")
	}
}

func (app *ConnectionHandler) DeleteWebsocket(conn *ProxyWebsocketConnection) {
	app.wssConnectionsMutex.Lock()
	defer app.wssConnectionsMutex.Unlock()
	index := slices.Index(app.wssConnections, conn)
	if index == -1 {
		log.Print("error: unable to delete: index not found")
		return
	}
	app.wssConnections = slices.Delete(app.wssConnections, index, index+1)
}

func (connection *ProxyLocalConnection) QueueAndSend(message []byte) error {
	// first 4 bytes contain sequenceID
	if len(message) < 5 {
		return fmt.Errorf("Unable to queue and send: message is too short to contain valid framing!")
	}

	messageSquenceId := binary.BigEndian.Uint32(message[:4])
	messagePayload := message[4:]

	// log.Print("Writing message payload: ", len(messagePayload), " bytes, sequence ID: ", messageSquenceId)

	if messageSquenceId-uint32(connection.expectedSequenceId.Load()) > 500 {
		return fmt.Errorf("Message sequence ID deviates too far from expected sequence ID! (>500)")
	}

	tcpConnection := connection.localConnection

	// Reordering logic -- reorders packets for correct order

	connection.queuedPacketsMu.Lock()
	// Add it to the queue
	connection.queuedPackets[int64(messageSquenceId)] = messagePayload

	for {
		// check if sequence ID now exists
		expectedSequenceIdCurrent := connection.expectedSequenceId.Load()
		currentMessage, exists := connection.queuedPackets[expectedSequenceIdCurrent]
		if !exists {
			// log.Print("Sequence ID: ", expectedSequenceIdCurrent, " does not exist. Breaking out of the loop\nNumber of packets to be reordered: ", len(connection.queuedPackets))
			break
		}

		// Deliver the payload
		// log.Print("Sent sequence ID: ", expectedSequenceIdCurrent, " to destination")
		tcpConnection.Write(currentMessage)

		// Remove from the list
		delete(connection.queuedPackets, expectedSequenceIdCurrent)

		// Increment sequence ID
		connection.expectedSequenceId.Add(1)

		// log.Print("Message originally received and sent to TCP: ", base64.StdEncoding.EncodeToString(currentMessage))
		// log.Printf("Originally received sum: %x\n", sha256.Sum256(currentMessage))
	}
	connection.queuedPacketsMu.Unlock()

	return nil
}

func (app *ConnectionHandler) SendAnyWebsocket(payload []byte) {
	// if there are any active
	app.activeConnectionIndexesMu.RLock()
	defer app.activeConnectionIndexesMu.RUnlock()

	attempts := 0

	for {

		if attempts >= 50 {
			log.Print("error: failed to send to any websocket. failed after 50 attempts")
			return
		}

		activeConnections := app.activeConnectionIndexes

		if len(activeConnections) <= 0 {
			log.Print("error: cannot send, no active connections. queuing for retransmit")
			app.toBeRetransmittedPackets = append(app.toBeRetransmittedPackets, payload)
			return
		}

		// take any connection
		curretCounter := app.roundRobinCounter.Load()
		app.roundRobinCounter.Add(1)
		targetConnectionIndex := app.activeConnectionIndexes[curretCounter%int64(len(app.activeConnectionIndexes))]

		app.wssConnectionsMutex.Lock()
		targetConnection := app.wssConnections[targetConnectionIndex]
		app.wssConnectionsMutex.Unlock()

		// send it onto that connection
		err := targetConnection.connection.WriteMessage(websocket.BinaryMessage, payload)
		if err != nil {
			log.Print("Failed to send, attempting to retry")
			attempts++
		} else {
			return
		}
	}

}

func (app *ConnectionHandler) SendSignal(messageType MessageType, payload []byte) {
	currentSeqId := app.currentSendSequenceId.Load()
	app.currentSendSequenceId.Add(1)

	seqIdBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(seqIdBuf, uint32(currentSeqId))

	msgPayload := append(append([]byte{messageType}, seqIdBuf...), payload...)

	app.SendAnyWebsocket(msgPayload)
}

func (app *ConnectionHandler) ForwardPacketToWebsocket(conn *ProxyLocalConnection, payload []byte, clientId byte, sequenceId int64) {
	app.SendWebsocketRoundRobinEncrypt(clientId, payload)

	// Write to to be acknowledged
	conn.toBeAcknowledgedPacketsMu.Lock()
	conn.toBeAcknowledgedPackets[sequenceId] = payload
	conn.toBeAcknowledgedPacketsMu.Unlock()
}

func (app *ConnectionHandler) HandleWebsocketMessage(conn *ProxyWebsocketConnection, messageType MessageType, message []byte) error {
	if message[0] == 0 { // means network packet

		if !conn.ready.Load() {
			log.Print("ignored packet: connection is not ready")
			return nil
		}

		// forward
		clientId := message[1] // client ID

		app.localConnectionsMutex.RLock()
		localConnection, exists := app.localConnections[int(clientId)]
		app.localConnectionsMutex.RUnlock()
		if !exists {
			log.Print("ignoring packet: client ID ", clientId, " not found")
			return nil
		}
		// log.Print("received ", len(message)-2, " from websocket")

		plaintext, err := Decrypt(conn.sharedSecret, message[2:])
		if err != nil {
			log.Print("error: failed to decrypt: ", err)
			return nil
		}

		err = localConnection.QueueAndSend(plaintext)
		if err != nil {
			log.Print("error: failed to forward packet: ", err)
			return nil
		}
	} else if message[0] == 1 { // means client ready

		if !(conn.protocolCompletion.KyberHandshakeReceived) {
			log.Print("error: cannot verify signature without kyber handshake")
			return fmt.Errorf("cannot verify signature without kyber handshake")
		}

		log.Print("Connection reported established, need to verify key match")
		log.Printf("handshake transcript signature (EdDSA): %x\n", message[1:])
		valid := VerifySignature(CERTIFICATE_PUBLIC_KEY, conn.handshakeTranscript, message[1:])
		if !valid {
			log.Print("--- MAN IN THE MIDDLE TAMPERING DETECTED ---")
			log.Fatal("Ending all connections immediately")
			return fmt.Errorf("MITM attack detected")
		}
		log.Print("valid signature detected, trusting server")

		// we need to verify key confirmation and transcript
		transcriptHash := sha256.Sum256(conn.handshakeTranscript)
		prk, err := hkdf.Extract(sha256.New, conn.sharedSecret, transcriptHash[:])
		if err != nil {
			log.Print("error: hkdf failed to extract: ", err)
			return fmt.Errorf("hkdf failed to extract")
		}
		confirmKey, err := hkdf.Expand(sha256.New, prk, "confirm", 32)
		if err != nil {
			log.Print("error: hkdf failed to expand: ", err)
			return fmt.Errorf("hkdf failed to expand")
		}

		log.Print("Derived key: ", len(confirmKey), " bytes")

		mac := hmac.New(sha256.New, confirmKey)
		mac.Write(conn.handshakeTranscript)
		mac.Write([]byte("client"))
		clientConfirm := mac.Sum(nil)

		clientMac := clientConfirm

		payload := append([]byte{5}, clientMac...) // 5 is key confirmation

		conn.connection.WriteMessage(websocket.BinaryMessage, payload)

		log.Print("sent confirmation to server: ", len(payload), " bytes")

		conn.protocolCompletion.SignatureReceived = true

	} else if message[0] == 2 { // server requested disconnect

		if !conn.ready.Load() {
			log.Print("error: cannot perform disconnect when connection is not ready")
			return nil
		}

		clientId := message[1]

		app.localConnectionsMutex.Lock()
		localConnection, exists := app.localConnections[int(clientId)]

		if !exists {
			log.Print("ignoring disconnect: client ID ", clientId, " not found")
			app.localConnectionsMutex.Unlock()
			return nil
		}

		localConnection.localConnection.Close()
		log.Print("closed connection ", clientId, " as requested by server")
		delete(app.localConnections, int(clientId))
		app.localConnectionsMutex.Unlock()

		app.clientConnectionIDsRWMutex.Lock()
		_, exists = app.clientConnectionIDs[int(clientId)]
		if !exists {
			log.Print("does not exist in clientid")
			app.clientConnectionIDsRWMutex.Unlock()
			return nil
		}
		delete(app.clientConnectionIDs, int(clientId))
		app.clientConnectionIDsRWMutex.Unlock()
		log.Print("deleted client id entry: ", clientId)
	} else if message[0] == 3 { // means handshake data
		log.Print("received handshake")
		conn.handshakeTranscript = append(conn.handshakeTranscript, message...)
		publicKeyBin := message[1:]
		publicKey, err := conn.scheme.UnmarshalBinaryPublicKey(publicKeyBin)
		if err != nil {
			log.Print("error: handshake failed: failed to unmarshal key: ", err)
			return fmt.Errorf("failed to unmarshal key")
		}

		ciphertext, sharedSecret, err := conn.scheme.Encapsulate(publicKey)
		if err != nil {
			log.Print("error: handshake failed: failed to encapsulate key: ", err)
			return fmt.Errorf("failed to encapsulate key")
		}

		conn.sharedSecret = sharedSecret

		conn.writeMutex.Lock()
		payload := append([]byte{3}, ciphertext...)
		conn.connection.WriteMessage(websocket.BinaryMessage, payload)
		conn.handshakeTranscript = append(conn.handshakeTranscript, payload...)
		conn.writeMutex.Unlock()
		log.Print("wrote ciphertext")

		conn.protocolCompletion.KyberHandshakeReceived = true

	} else if message[0] == 6 {

		if !(conn.protocolCompletion.KyberHandshakeReceived && conn.protocolCompletion.SignatureReceived) {
			log.Print("error: cannot confirm key before kyber handshake and signature validation")
			return fmt.Errorf("wrong order handshake")
		}

		serverMac := message[1:]

		// derive key again
		transcriptHash := sha256.Sum256(conn.handshakeTranscript)
		prk, err := hkdf.Extract(sha256.New, conn.sharedSecret, transcriptHash[:])
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
		mac.Write(conn.handshakeTranscript)
		mac.Write([]byte("server"))

		if !hmac.Equal(serverMac, mac.Sum(nil)) {
			log.Print("error: authenticity verification failed: HMAC mismatch, ending connection")
			return fmt.Errorf("authentication failed")
		} else {
			conn.protocolCompletion.KeyConfirmationReceived = true
			log.Print("passed key confirmation check")

			if !(conn.protocolCompletion.KeyConfirmationReceived == true && conn.protocolCompletion.KyberHandshakeReceived == true && conn.protocolCompletion.SignatureReceived == true) {
				log.Print("error: invalid handshake. skipped one or more steps")
				return fmt.Errorf("not all steps complete")
			} else {
				log.Print("protocol handshake complete")
			}

			conn.ready.Store(true)
			// find out index
			app.wssConnectionsMutex.RLock()
			index := slices.Index(app.wssConnections, conn)
			app.wssConnectionsMutex.RUnlock()
			if index != -1 {
				app.activeConnectionIndexesMu.Lock()
				app.activeConnectionIndexes = append(app.activeConnectionIndexes, index)
				app.activeConnectionIndexesMu.Unlock()
			}

			log.Print("connection is ready")
			conn.handshakeSucceeded.Store(true)
			log.Print("marked handshake succeeded")

		}
	} else {
		log.Print("error: unrecognized message type: ", message[0])
	}
}

func (app *ConnectionHandler) HandleWebsocketRead(conn *ProxyWebsocketConnection) {
	defer conn.connection.Close()
	defer app.onSocketDied(conn)
	defer app.DeleteWebsocket(conn)

	// first send message 4, which is clientHello
	nonce, err := GenerateSecureSecret()
	if err != nil {
		log.Print("error: failed to generate nonce")
		return
	}
	payloadNonce := append([]byte{4}, nonce...)
	app.SendSignal(MessageTypeClientHello, nonce)
	conn.handshakeTranscript = append(conn.handshakeTranscript, payloadNonce...)
	log.Print("sent client hello nonce")

	// step-by-step protocol

	for {
		_, message, err := conn.connection.ReadMessage()
		if err != nil {
			log.Print("Proxy Websocket Disconnected")
			conn.ready.Store(false)
			// get index
			app.wssConnectionsMutex.RLock()
			index := slices.Index(app.wssConnections, conn)
			app.wssConnectionsMutex.RUnlock()
			if index != -1 {
				app.activeConnectionIndexesMu.Lock()
				i := slices.Index(app.activeConnectionIndexes, index)
				app.activeConnectionIndexes = append(app.activeConnectionIndexes[:i], app.activeConnectionIndexes[i+1:]...)
				app.activeConnectionIndexesMu.Unlock()
			}
			break
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

func (app *ConnectionHandler) AssignConnectionHandler() int {
	// find a right connection to assign to
	leastWebsocketCount := 99999
	leastWebsocketCountIndex := -1

	app.wssConnectionsMutex.RLock()

	for index, wssConnection := range app.wssConnections {
		if int(wssConnection.connectedCount.Load()) < leastWebsocketCount && wssConnection.ready.Load() {
			leastWebsocketCountIndex = index
			leastWebsocketCount = int(wssConnection.connectedCount.Load())
		}
	}

	app.wssConnectionsMutex.RUnlock()

	return leastWebsocketCountIndex
}

func (app *ConnectionHandler) FindChosenWebsocketVictim() *ProxyWebsocketConnection {
	app.wssConnectionsMutex.RLock()
	defer app.wssConnectionsMutex.RUnlock()
	var leastConnectionsSocket *ProxyWebsocketConnection
	leastConnectionsCount := 999999
	for _, wssConnection := range app.wssConnections {
		if wssConnection.connectedCount.Load() < int64(leastConnectionsCount) {
			leastConnectionsCount = int(wssConnection.connectedCount.Load())
			leastConnectionsSocket = wssConnection
		}
	}
	return leastConnectionsSocket

}

func (app *ConnectionHandler) MultiplexingScalingLoop() {
	ticker := time.NewTicker(time.Second)

	for range ticker.C {
		// calculate average connections per socket
		connectionsPerSocketSum := 0
		app.wssConnectionsMutex.RLock()
		for _, wssConnection := range app.wssConnections {
			connectionsPerSocketSum += int(wssConnection.connectedCount.Load())
		}
		connectionsPerSocketAvg := float32(connectionsPerSocketSum) / float32(len(app.wssConnections))
		app.wssConnectionsMutex.RUnlock()

		log.Print("scaling: connections per socket: ", connectionsPerSocketAvg)

		// levels
		// < 2 --> drop
		// > 5 --> add

		if connectionsPerSocketAvg < 6 {
			log.Print("attempting to downscale")
			// don't downscale to less than 2
			if len(app.wssConnections) <= 2 {
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
			leastWorthySocket.intentionallyDisconnected.Store(true)
			leastWorthySocket.connection.Close()
		} else if connectionsPerSocketAvg > 12 {
			log.Print("attempting to upscale")

			if len(app.wssConnections) >= NUMBER_OF_CONNECTIONS {
				log.Print("not upscaling, reached maximum wss connection count")
			}

			log.Print("creating websocket")
			app.CreateWebSocket()
		} else {
			log.Print("scaling ok -- multiplex: ", len(app.wssConnections), " /  connections per socket avg: ", connectionsPerSocketAvg, " / sum: ", connectionsPerSocketSum)
		}
	}
}

func (app *ConnectionHandler) GetActiveConnections() []int {
	return app.activeConnectionIndexes
}

func (app *ConnectionHandler) SendWebsocketRoundRobinEncrypt(clientId byte, message []byte) {

	app.wssConnectionsMutex.RLock()
	defer app.wssConnectionsMutex.RUnlock()

	firstIndexTried := -1

	for {
		activeConnections := app.GetActiveConnections()
		if len(activeConnections) <= 0 {
			log.Print("cannot divide by 0")
			return
		}
		currentIndexPointer := int(app.roundRobinCounter.Load() % int64(len(activeConnections)))
		app.roundRobinCounter.Add(1)
		currentIndex := activeConnections[currentIndexPointer]

		targetSocket := app.wssConnections[currentIndex]

		//data := append(sequenceIdBuf, buf[:n]...)
		// forward directly, but append data first
		ciphertext, err := Encrypt(targetSocket.sharedSecret, message)
		if err != nil {
			log.Print("error: failed to encrypt: ", err)
			continue
		}

		forwardData := append([]byte{0, byte(clientId)}, ciphertext...)

		targetSocket.writeMutex.Lock()
		err = targetSocket.connection.WriteMessage(websocket.BinaryMessage, forwardData)
		targetSocket.writeMutex.Unlock()
		if err != nil {
			log.Print("failed to send, retrying")
			if firstIndexTried == -1 {
				firstIndexTried = currentIndex
			} else {
				if firstIndexTried == currentIndex {
					log.Print("looped back to first, all websockets failed to send")
					return
				}
			}
		} else {
			// log.Print("Message originally sent to server: ", message)
			return
		}
	}

}

func (app *ConnectionHandler) HandleNewConnection(conn net.Conn) {

	log.Print("new tcp connection")

	leastWebsocketCountIndex := app.AssignConnectionHandler()

	if leastWebsocketCountIndex == -1 {
		log.Print("error: unable to connect. No websockets are active and ready at this time")
		conn.Close()
		return
	} else {
		log.Print("allocated connection to #", leastWebsocketCountIndex)
	}

	app.wssConnectionsMutex.RLock()
	wsSocket := app.wssConnections[leastWebsocketCountIndex]
	app.wssConnectionsMutex.RUnlock()

	clientId := app.reserveClientID()
	log.Print("got client: ", clientId)
	if clientId == -1 {
		log.Print("error: connection failed. failed to reserve client id")
		conn.Close()
		return
	}

	wsSocket.connectedCount.Add(1)
	// make sure to decrement connected count
	defer func() {
		wsSocket.connectedCount.Add(-1)
	}()

	app.localConnectionsMutex.Lock()
	localConnection := &ProxyLocalConnection{
		localConnection:    conn,
		wssConnectionIndex: leastWebsocketCountIndex,
		destination:        "",
		wssConnectionid:    clientId,
		queuedPackets:      make(map[int64][]byte),
		queuedPacketsMu:    sync.RWMutex{},
		sequenceId:         atomic.Int64{},
		expectedSequenceId: atomic.Int64{},
	}
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
				app.SendSignal(MessageTypeStreamDisconnect, []byte{byte(clientId)})

				// make sure to unreserve it
				app.clientConnectionIDsRWMutex.Lock()
				delete(app.clientConnectionIDs, clientId)
				app.clientConnectionIDsRWMutex.Unlock()

			}
			return
		}

		// sequence id
		currentSequenceId := localConnection.sequenceId.Load()
		localConnection.sequenceId.Add(1)
		sequenceIdBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(sequenceIdBuf, uint32(currentSequenceId))
		// data
		data := append(sequenceIdBuf, buf[:n]...)

		// log.Print("received ", n, " bytes from TCP")

		// write

		//
		// log.Printf("sent message sum sha256: %x\n", sha256.Sum256(buf[:n]))
		// log.Print("Message sent to server: ", base64.StdEncoding.EncodeToString(buf[:n]))

		app.SendWebsocketRoundRobinEncrypt(byte(clientId), data)

	}
}
