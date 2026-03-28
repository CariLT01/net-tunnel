package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/gorilla/websocket"
)

func (session *Session) WebsocketWriteMessage(conn *WebsocketConnection, message []byte) error {
	conn.writeMutex.Lock()
	err := conn.connection.WriteMessage(websocket.BinaryMessage, message)
	conn.writeMutex.Unlock()
	return err
}

func GetDialTarget(msg []byte) (string, error) {
	// Split headers from the first line
	lines := bytes.SplitN(msg, []byte("\r\n"), 2)
	if len(lines) == 0 {
		return "", fmt.Errorf("empty message")
	}

	requestLine := string(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid request line")
	}

	method := parts[0]

	// -------------------------
	// Case 1: CONNECT (HTTPS)
	// -------------------------
	if method == "CONNECT" {
		target := parts[1] // already host:port

		// Ensure port exists (default 443)
		if !strings.Contains(target, ":") {
			target = target + ":443"
		}

		return target, nil
	}

	// -------------------------
	// Case 2: HTTP request
	// -------------------------
	rawURL := parts[1]

	// Parse URL if absolute
	u, err := url.Parse(rawURL)
	if err == nil && u.Host != "" {
		host := u.Host

		// Default HTTP port
		if !strings.Contains(host, ":") {
			host += ":80"
		}

		return host, nil
	}

	// Fallback: extract Host header
	headers := bytes.Split(msg, []byte("\r\n"))
	for _, h := range headers {
		if bytes.HasPrefix(bytes.ToLower(h), []byte("host:")) {
			host := strings.TrimSpace(string(h[5:]))

			if !strings.Contains(host, ":") {
				host += ":80"
			}

			return host, nil
		}
	}

	return "", fmt.Errorf("could not determine target host")
}

func (session *Session) HandleTCPConnection(conn net.Conn, wsConn *WebsocketConnection, clientId int) {
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Print("detected tcp socket closed. error: ", err)
			if clientId != -1 {
				log.Print("writing disconnect to server")
				writeErr := session.WebsocketWriteMessage(wsConn, []byte{2, byte(clientId)})
				if writeErr != nil {
					log.Print("error: unable to write disconnect: ", writeErr)
				}
			}
			return
		}
		// log.Print("received ", n, " bytes from TCP socket")

		data := buf[:n]
		// forward directly, but append data first
		ct, err := Encrypt(wsConn.sharedSecret, data)
		if err != nil {
			log.Print("failed to encrypt: ", err)
			continue
		}
		forwardData := append([]byte{0, byte(clientId)}, ct...)

		session.WebsocketWriteMessage(wsConn, forwardData)

	}
}

func (session *Session) HandleWebsocketLoop(conn *WebsocketConnection) {

	session.clientsActive.Add(1)
	defer conn.connection.Close()
	defer session.clientsActive.Add(-1)

	scheme := kyber768.Scheme()

	ready := false
	var sharedSecret []byte
	publicKey, privateKey, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		log.Print("error: failed to generate keypair", err)
		return
	}

	publicKeyBin, err := publicKey.MarshalBinary()
	if err != nil {
		log.Print("error: unable to pack public key", err)
		return
	}

	// send public key
	log.Print("writing public key")
	conn.connection.WriteMessage(websocket.BinaryMessage, append([]byte{3}, publicKeyBin...))

	//server.WebsocketWriteMessage(conn, []byte{1}) // send READY status immediately

	for {
		_, message, err := conn.connection.ReadMessage()
		if err != nil {
			log.Print("error: failed to read: ", err)
			return
		}

		session.lastActiveTime = time.Now()

		if message[0] == 0 {
			// is a network packet
			if !ready {
				log.Print("warn: ignored packet received during handshake")
				continue
			}

			clientID := message[1]
			tcpConn, exists := session.clientIDs[int(clientID)]
			plaintext, err := Decrypt(conn.sharedSecret, message[2:])
			if err != nil {
				log.Print("error: failed to decrypt: ", err)
				continue
			}
			messagePayload := plaintext
			if !exists {
				log.Print("unknown client id ", clientID, " attempting to dial")

				host, hostError := GetDialTarget(messagePayload)
				if hostError != nil {
					log.Print("error: unable to resolve dial destination: ", hostError)
				}
				log.Print("dial attempt: ", host)
				tcpConn, err := net.Dial("tcp", host)
				if err != nil {
					log.Print("error: unable to dial destination: ", err)
					continue
				}
				log.Print("connection dialed successfully")
				go session.HandleTCPConnection(tcpConn, conn, int(clientID))
				//log.Print("writing ", messagePayload)
				//tcpConn.Write(messagePayload)

				msgEstablished := []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
				ct, err := Encrypt(conn.sharedSecret, msgEstablished)
				if err != nil {
					log.Print("failed to encrypt handshake: ", err)
					continue
				}
				err = session.WebsocketWriteMessage(conn, append([]byte{0, clientID}, ct...)) // apparently...
				if err != nil {
					log.Print("failed to write handshake: ", err)
				}

				session.clientIDsMu.Lock()
				session.clientIDs[int(clientID)] = &tcpConn
				session.clientIDsMu.Unlock()
			} else {
				// log.Print("received ", len(message)-2, " from websocket")
				(*tcpConn).Write(messagePayload)
			}
		} else if message[0] == 3 {
			ciphertext := message[1:]
			sharedSecret, err = scheme.Decapsulate(privateKey, ciphertext)
			if err != nil {
				log.Print("error: handshake failed: decapsulate failed: ", err)
				return
			}
			conn.connection.WriteMessage(websocket.BinaryMessage, []byte{1})
			ready = true
			log.Print("encryption handshake complete")
			log.Print("shared secret length: ", len(sharedSecret))
			conn.sharedSecret = sharedSecret
		}

	}
}

func (server *Server) HandleSessionsCleanup() {
	ticker := time.NewTicker(time.Second * 30)
	for range ticker.C {
		log.Print("run cleanup")
		server.sessionsMu.Lock()

		for sessionId, session := range server.sessions {
			if time.Since(session.lastActiveTime) >= time.Second*30 && session.clientsActive.Load() <= 0 {
				log.Print("deleting session")
				delete(server.sessions, sessionId)
			}
		}
		server.sessionsMu.Unlock()
	}

}

func (server *Server) HandleSessionCreationRequest(w http.ResponseWriter, r *http.Request) {
	// generate a random session id
	attempts := 0
	for {
		sessionId, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
		if err != nil {
			log.Print("error: failed to generate a random number lol")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "{\"ok\":false}")
			return
		} else {
			// create session
			server.sessionsMu.RLock()
			_, exists := server.sessions[int(sessionId.Int64())]
			server.sessionsMu.RUnlock()
			if exists {
				attempts += 1
				if attempts >= 5000 {
					log.Print("error: cannot create session: map too saturated")
					w.WriteHeader(http.StatusServiceUnavailable)
					fmt.Fprintln(w, "{\"ok\":false}")
					return
				}
				continue
			}
			session := NewSession()
			server.sessionsMu.Lock()
			server.sessions[int(sessionId.Int64())] = session
			server.sessionsMu.Unlock()
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "{\"ok\":true,\"data\":"+sessionId.String()+"}")

			return

		}
	}

}

func (server *Server) HandleWebsocketRequest(w http.ResponseWriter, r *http.Request) {
	conn, err := server.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("error: failed to upgrade connection: ", err)
		return
	}

	values := r.URL.Query()
	sessionId := values.Get("sessionId")
	if sessionId == "" {
		log.Print("client did not provide session id")
		conn.Close()
		return
	}
	sessionIdInt, err := strconv.Atoi(sessionId)
	if err != nil {
		log.Print("client did not provide integer session id")
		conn.Close()
		return
	}

	server.sessionsMu.RLock()
	session, exists := server.sessions[sessionIdInt]
	server.sessionsMu.RUnlock()
	if !exists {
		log.Print("session does not exist")
		conn.Close()
		return
	}

	connectionObject := &WebsocketConnection{
		connection: conn,
		writeMutex: sync.Mutex{},
	}

	go session.HandleWebsocketLoop(connectionObject)
}
