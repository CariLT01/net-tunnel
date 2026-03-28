package main

import (
	"encoding/json"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/gorilla/websocket"
)

type SessionCreationResponse struct {
	Ok   bool `json:"ok"`
	Data *int `json:"data"`
}

func (app *ConnectionHandler) connectToWebsocket() *ProxyWebsocketConnection {
	u := url.URL{Scheme: "ws", Host: RELAY_URL, Path: "/stream"}
	q := u.Query()
	q.Set("sessionId", strconv.Itoa(app.sessionId))
	u.RawQuery = q.Encode()
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("Failed to dial")
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

func (app *ConnectionHandler) HandleWebsocketRead(conn *ProxyWebsocketConnection) {
	defer conn.connection.Close()
	defer app.onSocketDied(conn)

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
			conn.ready = true
		} else if message[0] == 2 { // server requested disconnect
			clientId := message[1]

			app.localConnectionsMutex.RLock()
			localConnection, exists := app.localConnections[int(clientId)]
			app.localConnectionsMutex.RUnlock()

			if !exists {
				log.Print("ignoring disconnect: client ID ", clientId, " not found")
				continue
			}

			localConnection.localConnection.Close()
			log.Print("closed connection ", clientId, " as requested by server")
		} else if message[0] == 3 {
			log.Print("received handshake")
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
			conn.connection.WriteMessage(websocket.BinaryMessage, append([]byte{3}, ciphertext...))
			conn.writeMutex.Unlock()
			log.Print("wrote ciphertext")

		}
	}
}

func (app *ConnectionHandler) CreateWebSocket() {
	socketObj := app.connectToWebsocket()
	go app.HandleWebsocketRead(socketObj)
}

func (app *ConnectionHandler) CreateSession() {
	u := url.URL{Scheme: "http", Host: RELAY_URL, Path: "/session/create"}
	resp, err := http.Get(u.String())
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("failed to read body: ", err)
	}

	var r SessionCreationResponse
	json.Unmarshal(body, &r)

	if r.Ok == false {
		log.Fatal("failed to create session: server returned ok=false")
	}
	if r.Data == nil {
		log.Fatal("failed to create session. server returned ok=true but data=nil")
	}

	app.sessionId = *r.Data

	log.Print("created session id: ", app.sessionId)
}

func (app *ConnectionHandler) Initialize() {

	app.CreateSession()

	for i := 0; i < NUMBER_OF_CONNECTIONS; i++ {
		app.CreateWebSocket()
		log.Print("Connection #", i, " created")
	}
}

func (app *ConnectionHandler) SocketWriteMessage(socket *ProxyWebsocketConnection, message []byte) error {
	socket.writeMutex.Lock()
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

				// make sure to decrement connected count
				wsSocket.connectedCount.Add(-1)
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

			leastWebsocketCountIndex = app.AssignConnectionHandler()
			if leastWebsocketCountIndex == -1 {
				log.Print("nothing to reassign to, disconnecting")
				return
			}

			app.wssConnectionsMutex.RLock()
			wsSocket = app.wssConnections[leastWebsocketCountIndex]
			app.wssConnectionsMutex.RUnlock()

			localConnection.wssConnectionIndex = leastWebsocketCountIndex

			// resend!

			err := app.SocketWriteMessage(wsSocket, forwardData)
			if err != nil {
				log.Print("new reassigned socket still cannot be written to: ", err, " disconnecting socket")
				return
			}
		}

	}
}
