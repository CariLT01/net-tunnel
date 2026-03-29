package main

import (
	"encoding/json"
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
	SessionId     *int    `json:"sessionId"`
	IdentityToken *string `json:"identityToken"`
}

func (app *ConnectionHandler) connectToWebsocket() *ProxyWebsocketConnection {
	u := url.URL{Scheme: SCHEME_WS, Host: RELAY_URL, Path: "/stream"}
	q := u.Query()
	q.Set("sessionId", strconv.Itoa(app.sessionId))

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+app.identityToken)

	u.RawQuery = q.Encode()
	c, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}

	connectionObj := &ProxyWebsocketConnection{
		ready:          false,
		connection:     c,
		connectedCount: atomic.Int64{},
		writeMutex:     sync.Mutex{},
	}

	app.wssConnectionsMutex.Lock()
	app.wssConnections = append(app.wssConnections, connectionObj)
	app.wssConnectionsMutex.Unlock()

	return connectionObj
}

func (app *ConnectionHandler) onSocketDied(conn *ProxyWebsocketConnection) {
	if conn.ready {
		// only if it was actually ready
		// don't want to be stuck in a never-ending loop of unsuccessful sockets
		app.CreateWebSocket()
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

func (app *ConnectionHandler) HandleWebsocketRead(conn *ProxyWebsocketConnection) {
	defer conn.connection.Close()
	defer app.onSocketDied(conn)
	defer app.DeleteWebsocket(conn)

	scheme := kyber768.Scheme()

	for {
		_, message, err := conn.connection.ReadMessage()
		if err != nil {
			log.Print("Proxy Websocket Disconnected")
			conn.ready = false
			break
		}

		if message[0] == 0 { // means network packet
			// forward
			clientId := message[1] // client ID

			app.localConnectionsMutex.RLock()
			localConnection, exists := app.localConnections[int(clientId)]
			app.localConnectionsMutex.RUnlock()
			if !exists {
				log.Print("ignoring packet: client ID ", clientId, " not found")
				continue
			}
			// log.Print("received ", len(message)-2, " from websocket")

			plaintext, err := Decrypt(conn.sharedSecret, message[2:])
			if err != nil {
				log.Print("error: failed to decrypt: ", err)
				continue
			}

			localConnection.localConnection.Write(plaintext)
		} else if message[0] == 1 { // means client ready
			log.Print("Connection reported ready")
			log.Print("signature: ", message[1:])
			valid := VerifySignature(CERTIFICATE_PUBLIC_KEY, conn.handshakeTranscript, message[1:])
			if !valid {
				log.Print("--- MAN IN THE MIDDLE TAMPERING DETECTED ---")
				log.Fatal("Ending all connections immediately")
				return
			}
			log.Print("valid signature detected, trusting server")
			conn.ready = true
		} else if message[0] == 2 { // server requested disconnect
			clientId := message[1]

			app.localConnectionsMutex.Lock()
			localConnection, exists := app.localConnections[int(clientId)]

			if !exists {
				log.Print("ignoring disconnect: client ID ", clientId, " not found")
				app.localConnectionsMutex.Unlock()
				continue
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
				continue
			}
			delete(app.clientConnectionIDs, int(clientId))
			app.clientConnectionIDsRWMutex.Unlock()
			log.Print("deleted client id entry: ", clientId)
		} else if message[0] == 3 { // means handshake data
			log.Print("received handshake")
			conn.handshakeTranscript = append(conn.handshakeTranscript, message...)
			publicKeyBin := message[1:]
			publicKey, err := scheme.UnmarshalBinaryPublicKey(publicKeyBin)
			if err != nil {
				log.Print("error: handshake failed: failed to unmarshal key: ", err)
				return
			}

			ciphertext, sharedSecret, err := scheme.Encapsulate(publicKey)
			if err != nil {
				log.Print("error: handshake failed: failed to encapsulate key: ", err)
				return
			}

			conn.sharedSecret = sharedSecret

			conn.writeMutex.Lock()
			payload := append([]byte{3}, ciphertext...)
			conn.connection.WriteMessage(websocket.BinaryMessage, payload)
			conn.handshakeTranscript = append(conn.handshakeTranscript, payload...)
			conn.writeMutex.Unlock()
			log.Print("wrote ciphertext")

		} else {
			log.Print("error: unrecognized message type: ", message[0])
		}
	}
}

func (app *ConnectionHandler) CreateWebSocket() {
	socketObj := app.connectToWebsocket()
	go app.HandleWebsocketRead(socketObj)
}

func (app *ConnectionHandler) CreateSession() {

	// solve pow

	sessionManager := SessionManager{}
	app.keys = sessionManager.FetchPublicKey()
	challengeToken, nonce := app.powSolver.GetChallengeAndSolve(app.keys)
	log.Print("challenge: ", challengeToken, " solution: ", nonce)
	log.Print("TEST 1")

	u := url.URL{Scheme: SCHEME_HTTP, Host: RELAY_URL, Path: "/session/create"}
	q := u.Query()
	q.Set("challengeToken", challengeToken)
	q.Set("solution", strconv.FormatInt(nonce, 10))
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	log.Print("TEST 2")
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("failed to read body: ", err)
	}
	log.Print("TEST 3")

	// log.Print("body: " + string(body))

	var r SessionCreationResponse
	json.Unmarshal(body, &r)

	log.Print(r)

	if r.Ok == false {
		log.Fatal("failed to create session: server returned ok=false")
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

	app.CreateSession()

	for i := 0; i < 2; i++ {
		app.CreateWebSocket()
		log.Print("Connection #", i, " created")
	}

	go app.MultiplexingScalingLoop()
}

func (app *ConnectionHandler) SocketWriteMessage(socket *ProxyWebsocketConnection, message []byte) error {
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
		if int(wssConnection.connectedCount.Load()) < leastWebsocketCount && wssConnection.ready == true {
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
				writeErr := app.SocketWriteMessage(wsSocket, []byte{2, byte(clientId)})
				if writeErr != nil {
					log.Print("error: unable to write disconnect: ", writeErr)
				}

				// make sure to unreserve it
				app.clientConnectionIDsRWMutex.Lock()
				delete(app.clientConnectionIDs, clientId)
				app.clientConnectionIDsRWMutex.Unlock()

			}
			return
		}

		data := buf[:n]
		// forward directly, but append data first
		ciphertext, err := Encrypt(wsSocket.sharedSecret, data)
		if err != nil {
			log.Print("error: failed to encrypt: ", err)
			continue
		}
		forwardData := append([]byte{0, byte(clientId)}, ciphertext...)

		// log.Print("received ", n, " bytes from TCP")

		// write

		err = app.SocketWriteMessage(wsSocket, forwardData)
		if err != nil {
			log.Print("error: unable to write data, reassigning")
			attempts := 0
			oldStream := wsSocket
			for {
				if attempts >= 256 {
					log.Print("error: unable to reassign: too many attempts")
					return
				}

				leastWebsocketCountIndex = app.AssignConnectionHandler()
				if leastWebsocketCountIndex == -1 {
					log.Print("error: nothing to reassign to, disconnecting")
					return
				}

				app.wssConnectionsMutex.RLock()
				wsSocket = app.wssConnections[leastWebsocketCountIndex]
				app.wssConnectionsMutex.RUnlock()

				localConnection.wssConnectionIndex = leastWebsocketCountIndex

				// reencrypt
				ciphertext, err := Encrypt(wsSocket.sharedSecret, data)
				if err != nil {
					log.Print("error: failed to encrypt: ", err)
					continue
				}
				forwardData := append([]byte{0, byte(clientId)}, ciphertext...)

				// resend!
				err = app.SocketWriteMessage(wsSocket, forwardData)
				if err != nil {
					log.Print("error: new reassigned socket still cannot be written to: ", err, " retrying")
					attempts++
				} else {
					log.Print("reassigned to stream ", leastWebsocketCountIndex, " after ", attempts, " attempts")
					oldStream.connectedCount.Add(-1)
					wsSocket.connectedCount.Add(1)
					break
				}
			}

		}

	}
}
