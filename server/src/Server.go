package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

type SessionCreationResponse struct {
	Ok            bool    `json:"ok"`
	SessionId     *int    `json:"sessionId"`
	IdentityToken *string `json:"identityToken"`
}

func (session *Session) WebsocketWriteMessage(conn *WebsocketConnection, message []byte) error {
	conn.writeMutex.Lock()
	err := conn.connection.WriteMessage(websocket.BinaryMessage, message)
	conn.writeMutex.Unlock()
	session.lastActiveTime = time.Now()
	return err
}

func GetDialTarget(msg []byte) (string, string, error) {
	// Split headers from the first line
	lines := bytes.SplitN(msg, []byte("\r\n"), 2)
	if len(lines) == 0 {
		return "", "", fmt.Errorf("empty message")
	}

	requestLine := string(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid request line")
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

		return target, method, nil
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

		return host, method, nil
	}

	// Fallback: extract Host header
	headers := bytes.Split(msg, []byte("\r\n"))
	for _, h := range headers {
		if bytes.HasPrefix(bytes.ToLower(h), []byte("host:")) {
			host := strings.TrimSpace(string(h[5:]))

			if !strings.Contains(host, ":") {
				host += ":80"
			}

			return host, method, nil
		}
	}

	return "", "", fmt.Errorf("could not determine target host")
}

func (session *Session) SendAndReassign(wsConn *WebsocketConnection, clientId int, message []byte) *WebsocketConnection {

	ct, err := Encrypt(wsConn.sharedSecret, message)
	if err != nil {
		log.Print("failed to encrypt: ", err)
		return wsConn
	}

	// log.Print("forwarding ", len(ct), " bytes to wsConn")
	err = session.WebsocketWriteMessage(wsConn, append([]byte{0, byte(clientId)}, ct...))
	if err == nil {
		return wsConn
	} else {
		log.Print("need to reassign, first write failed")
	}

	attempts := 0
	for {

		if attempts > 256 {
			log.Print("error: failed to reassign: too many attempts")
			return nil
		}

		session.wssConnectionsMu.RLock()
		if len(session.wssConnections) == 0 {
			log.Print("error: nothing to reassign to, disconnecting")
			session.wssConnectionsMu.RUnlock()
			return nil
		}

		// search for any socket
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(session.wssConnections))))
		if err != nil {
			log.Print("error: failed to generate a random number, disconnecting")
			session.wssConnectionsMu.RUnlock()
			return nil
		}

		wsConn = session.wssConnections[randomIndex.Int64()]
		session.wssConnectionsMu.RUnlock()

		ct, err := Encrypt(wsConn.sharedSecret, message)
		if err != nil {
			log.Print("failed to encrypt: ", err)
			continue
		}

		err = session.WebsocketWriteMessage(wsConn, append([]byte{0, byte(clientId)}, ct...))
		if err != nil {
			log.Print("error: still unable to write, retrying")
			attempts++
		} else {
			log.Print("reassigned stream to #", randomIndex, " after ", attempts, " attempts")
			break
		}
	}

	return wsConn
}

func (session *Session) HandleTCPConnection(conn *TCPConnection, wsConn *WebsocketConnection, clientId int) {
	defer (*(conn.conn)).Close()
	defer func() {
		session.clientIDsMu.Lock()
		_, exists := session.clientIDs[clientId]
		if !exists {
			log.Print("error: unable to delete entry: client id doesn't exist")
			session.clientIDsMu.Unlock()
			return
		}
		delete(session.clientIDs, clientId)
		session.clientIDsMu.Unlock()
		log.Print("cleanup entry")
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := (*(conn.conn)).Read(buf)
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

		// reassign automatically

		// first wait
		session.limiterWait(session.outboundLimiter, len(data))

		newConn := session.SendAndReassign(wsConn, clientId, data)
		if newConn == nil {
			log.Print("error: unable to write: nothing to reassign to, disconnecting")
			return
		}
		wsConn = newConn

	}
}

func (session *Session) DeleteWebsocketConn(conn *WebsocketConnection) {
	session.wssConnectionsMu.Lock()
	defer session.wssConnectionsMu.Unlock()
	index := slices.Index(session.wssConnections, conn)
	if index == -1 {
		log.Print("error: unable to delete wss: index not found")
		return
	}
	session.wssConnections = slices.Delete(session.wssConnections, index, index+1)
	log.Print("deleted ", index, " from connections")
}

func (session *Session) limiterWait(limiter *rate.Limiter, n int) error {

	if err := limiter.WaitN(context.Background(), n); err != nil {
		return err
	}
	return nil
}

func (session *Session) HandleWebsocketLoop(conn *WebsocketConnection) {

	log.Print("detected new websocket")

	session.clientsActive.Add(1)
	defer conn.connection.Close()
	defer session.clientsActive.Add(-1)
	defer session.DeleteWebsocketConn(conn)

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
	payload := append([]byte{3}, publicKeyBin...)
	conn.handshakeTranscript = append(conn.handshakeTranscript, payload...)
	conn.connection.WriteMessage(websocket.BinaryMessage, payload)

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

			if len(message) < 2 {
				log.Print("error: message too short")
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

				host, method, hostError := GetDialTarget(messagePayload)
				if hostError != nil {
					log.Print("error: unable to resolve dial destination: ", hostError)
				}
				isConnect := method == "CONNECT"
				log.Print("dial attempt: ", host)
				tcpConn, err := net.Dial("tcp", host)
				if err != nil {
					log.Print("error: unable to dial destination: ", err)
					continue
				}
				log.Print("connection dialed successfully")

				tcpConnObj := &TCPConnection{
					conn: &tcpConn,
				}

				go session.HandleTCPConnection(tcpConnObj, conn, int(clientID))
				//log.Print("writing ", messagePayload)
				//tcpConn.Write(messagePayload)

				if isConnect {
					msgEstablished := []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
					// act as if the tcp connection sent this data
					session.limiterWait(session.outboundLimiter, len(msgEstablished))

					// ensure that the pending handshake data still goes somewhere
					// even if a websocket disconnects in the middle of all this logic

					newConn := session.SendAndReassign(conn, int(clientID), msgEstablished)
					if newConn == nil {
						log.Print("error: cannot send: no reassign")
						return
					}
					conn = newConn
				} else {
					tcpConn.Write(messagePayload)
				}

				session.clientIDsMu.Lock()
				session.clientIDs[int(clientID)] = tcpConnObj
				session.clientIDsMu.Unlock()
			} else {
				// log.Print("received ", len(message)-2, " from websocket")

				// rate limiting
				session.limiterWait(session.outboundLimiter, len(messagePayload))
				(*(tcpConn.conn)).Write(messagePayload)
			}
		} else if message[0] == 3 {
			conn.handshakeTranscript = append(conn.handshakeTranscript, message...)
			ciphertext := message[1:]
			sharedSecret, err = scheme.Decapsulate(privateKey, ciphertext)
			if err != nil {
				log.Print("error: handshake failed: decapsulate failed: ", err)
				return
			}

			transcriptSignature := Sign(CERTIFICATE_PRIVATE_KEY, conn.handshakeTranscript)

			conn.connection.WriteMessage(websocket.BinaryMessage, append([]byte{1}, transcriptSignature...))
			ready = true
			log.Print("encryption handshake complete")
			log.Print("shared secret length: ", len(sharedSecret))
			log.Print("transcript signature: ", transcriptSignature)
			conn.sharedSecret = sharedSecret
		} else if message[0] == 2 {

			clientID := message[1]
			session.clientIDsMu.Lock()
			tcpConn, exists := session.clientIDs[int(clientID)]
			if !exists {
				session.clientIDsMu.Unlock()
				log.Print("error: attempt to disconnect tcp conn that doesn't exist")
				continue
			}
			(*(tcpConn.conn)).Close()
			delete(session.clientIDs, int(clientID))
			session.clientIDsMu.Unlock()
			log.Print("deleted stream ", clientID)

		} else {
			log.Print("error: unrecognized message type: ", message[0])
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

func (server *Server) marshalSessionCreationResponse(ok bool, sessionId *int, identityToken *string) string {
	res := SessionCreationResponse{Ok: ok, SessionId: sessionId, IdentityToken: identityToken}
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return ""
	} else {
		return string(jsonBytes)
	}
}

func (server *Server) HandleSessionCreationRequest(w http.ResponseWriter, r *http.Request) {
	// generate a random session id
	values := r.URL.Query()

	challengeToken := values.Get("challengeToken")
	solution := values.Get("solution")

	if !server.verifier.VerifyProofOfWorkSolution(challengeToken, solution, "session-creation") {
		log.Print("client provided invalid proof of work challenge or solution")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Unauthorized: invalid challenge or solution")
		return
	}

	attempts := 0
	for {
		sessionId, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
		if err != nil {
			log.Print("error: failed to generate a random number lol")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, server.marshalSessionCreationResponse(false, nil, nil))
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
					fmt.Fprintln(w, server.marshalSessionCreationResponse(false, nil, nil))
					return
				}
				continue
			}

			identityToken, err := server.identityProvider.CreateIdentityToken(int(sessionId.Int64()))
			if err != nil {
				log.Print("error: failed to create identity token: ", err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, server.marshalSessionCreationResponse(false, nil, nil))
				return
			}

			session := NewSession()
			server.sessionsMu.Lock()
			server.sessions[int(sessionId.Int64())] = session
			server.sessionsMu.Unlock()
			w.WriteHeader(http.StatusOK)
			sessionIdInt := int(sessionId.Int64())
			log.Print("creating session id: ", sessionIdInt)
			fmt.Fprintln(w, server.marshalSessionCreationResponse(true, &sessionIdInt, &identityToken))

			return

		}
	}

}

func (server *Server) HandleWebsocketRequest(w http.ResponseWriter, r *http.Request) {

	values := r.URL.Query()
	sessionId := values.Get("sessionId")
	if sessionId == "" {
		log.Print("client did not provide session id")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Session ID not provided")
		return
	}
	sessionIdInt, err := strconv.Atoi(sessionId)
	if err != nil {
		log.Print("client did not provide integer session id")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Provided session ID is not an integer")
		return
	}

	identity := ""

	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		identity = strings.TrimPrefix(auth, "Bearer ")
	}

	if !server.identityProvider.VerifyIdentityToken(identity, sessionIdInt) {
		log.Print("invalid identity token or identity token does not match session")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Provided identity token is invalid or is not for this session")
		return
	}

	server.sessionsMu.RLock()
	session, exists := server.sessions[sessionIdInt]
	server.sessionsMu.RUnlock()
	if !exists {
		log.Print("session does not exist")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, "Session does not exist")
		return
	}

	session.wssConnectionsMu.RLock()
	length := len(session.wssConnections)
	session.wssConnectionsMu.RUnlock()
	if length >= 8 {
		log.Print("reached maximum number of wss connections per session")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "At or exceeded maximum number of streams per session")
		return
	}

	conn, err := server.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("error: failed to upgrade connection: ", err)
		return
	}

	connectionObject := &WebsocketConnection{
		connection: conn,
		writeMutex: sync.Mutex{},
	}

	session.wssConnectionsMu.Lock()
	session.wssConnections = append(session.wssConnections, connectionObject)
	session.wssConnectionsMu.Unlock()

	go session.HandleWebsocketLoop(connectionObject)
}

func (server *Server) HandleKeysEndpoint(w http.ResponseWriter, r *http.Request) {
	verifierPublicBase64 := base64.StdEncoding.EncodeToString(*server.verifier.publicKey)
	identityProviderPublicBase64 := base64.StdEncoding.EncodeToString(server.identityProvider.publicKey)
	res := KeysEndpointResponse{Ok: true, Keys: &KeysField{Challenge: &verifierPublicBase64, Identity: &identityProviderPublicBase64}}
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		log.Print("failed to marshal into json: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "{\"ok\":false}")
		return
	} else {
		jsonString := string(jsonBytes)
		log.Print("returning keys")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, jsonString)
		return
	}
}
