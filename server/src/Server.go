package main

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
	"sync/atomic"
	"time"

	shared "github.com/CariLT01/net-tunnel-common/shared"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

type SessionCreationResponse struct {
	Ok            bool    `json:"ok"`
	Message       string  `json:"message"`
	SessionId     *int    `json:"sessionId"`
	IdentityToken *string `json:"identityToken"`
}


type HandshakeProtocolCompletion struct {
	ClientHelloReceived   bool
	EncryptionEstablished bool
	KeyConfirmed          bool
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

func (session *Session) HandleTCPConnection(conn *shared.TCPStream, wsConn *shared.WSStream, clientId int) {
	defer conn.Connection.Close()
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
		n, err := conn.Connection.Read(buf)
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

		tcpSendPayload := conn.EncodePacketPayload(buf[:n])
		// first wait
		session.limiterWait(session.outboundLimiter, len(tcpSendPayload))

		// log.Printf("Sent message sum: %x\n", sha256.Sum256(buf[:n]))
		// log.Print("Message sent: ", base64.StdEncoding.EncodeToString(buf[:n]))
		session.multiplexer.SendData(shared.MessageTypeNetwork, append([]byte{byte(clientId)}, tcpSendPayload...))

	}
}

func (session *Session) limiterWait(limiter *rate.Limiter, n int) error {

	if err := limiter.WaitN(context.Background(), n); err != nil {
		return err
	}
	return nil
}

func (session *Session) ProcessSignalPacket(signalpacket *shared.SignalDecodedPacket) shared.PacketProcessingResult {
		if signalpacket.MessageType == shared.MessageTypeHandshake  {


			if !session.multiplexer.ProtocolCompletion.ClientHelloReceived {
				log.Print("error: protocol handshake failed: cannot establish encryption before client hello")
				return shared.PacketProcessingDisconnect
			}

			session.multiplexer.HandshakeTranscript = append(session.multiplexer.HandshakeTranscript, signalpacket.Payload...)
			//conn.AppendToTranscript(signalpacket.Payload)
			ciphertext := signalpacket.Payload
			sharedSecret, err := session.multiplexer.Scheme.Decapsulate(privateKey, ciphertext)
			if err != nil {
				log.Print("error: handshake failed: decapsulate failed: ", err)
				return shared.PacketProcessingDisconnect
			}
			session.multiplexer.SharedSecret = sharedSecret

			transcriptSignature := Sign(CERTIFICATE_PRIVATE_KEY, session.multiplexer.HandshakeTranscript)

			

			session.multiplexer.SendSignal(shared.MessageTypeSignature, transcriptSignature)

			log.Print("encryption handshake complete")
			log.Print("shared secret length: ", len(sharedSecret))
			log.Print("transcript signature: ", transcriptSignature)
			session.multiplexer.SharedSecret = sharedSecret
			session.multiplexer.ProtocolCompletion.EncryptionEstablished = true


		} else if signalpacket.MessageType == shared.MessageTypeStreamDisconnect {

			if !session.multiplexer.Ready.Load() {
				log.Print("cannot disconnect TCP connection with an unready connection")
				return shared.PacketProcessingDisconnect
			}

			clientID := signalpacket.Payload[0]
			session.clientIDsMu.Lock()
			tcpConn, exists := session.clientIDs[int(clientID)]
			if !exists {
				session.clientIDsMu.Unlock()
				log.Print("error: attempt to disconnect tcp conn that doesn't exist")
				return shared.PacketProcessingSkipped
			}
			tcpConn.Connection.Close()
			delete(session.clientIDs, int(clientID))
			session.clientIDsMu.Unlock()
			log.Print("deleted stream ", clientID)

		} else if signalpacket.MessageType == shared.MessageTypeClientHello {

			log.Print("received client hello nonce")
			session.multiplexer.HandshakeTranscript = append(session.multiplexer.HandshakeTranscript, signalpacket.Payload...)

			publicKeyBin, err := publicKey.MarshalBinary()
			if err != nil {
				log.Print("error: unable to pack public key", err)
				return shared.PacketProcessingDisconnect
			}

			// send public key
			log.Print("writing public key")
			
			payload := publicKeyBin

			session.multiplexer.HandshakeTranscript = append(session.multiplexer.HandshakeTranscript, payload)
			session.multiplexer.SendSignal(shared.MessageTypeHandshake, payload)

			session.multiplexer.ProtocolCompletion.ClientHelloReceived = true
		} else if signalpacket.MessageType == shared.MessageTypeReady {
			log.Print("received key confirmation message")

			if !(session.multiplexer.ProtocolCompletion.ClientHelloReceived && session.multiplexer.ProtocolCompletion.EncryptionEstablished) {
				log.Print("cannot confirm key without client hello and encryption establishment")
				return shared.PacketProcessingDisconnect
			}

			transcriptHash := sha256.Sum256(session.multiplexer.HandshakeTranscript)
			prk, err := hkdf.Extract(sha256.New, session.multiplexer.SharedSecret, transcriptHash[:])
			if err != nil {
				log.Print("error: hkdf failed to extract: ", err)
			}
			confirmKey, err := hkdf.Expand(sha256.New, prk, "confirm", 32)
			if err != nil {
				log.Print("error: hkdf failed to expand: ", err)
			}

			// my message
			mac := hmac.New(sha256.New, confirmKey)
			mac.Write(session.multiplexer.HandshakeTranscript)
			mac.Write([]byte("server"))

			macSum := mac.Sum(nil)

			// confirm client message
			macClient := hmac.New(sha256.New, confirmKey)
			macClient.Write(session.multiplexer.HandshakeTranscript)
			macClient.Write([]byte("client"))

			macClientSum := macClient.Sum(nil)

			if !hmac.Equal(macClientSum, signalpacket.Payload) {
				log.Print("error: key confirmation do not match, ending handshake")
				return shared.PacketProcessingDisconnect
			} else {
				log.Print("key confirmation matches")
			}

			// send back the confirmation
			// 6 -- final message

			session.multiplexer.SendSignal(shared.MessageTypeReady, macSum)

			log.Print("wrote server Mac, handshake complete")

			session.multiplexer.ProtocolCompletion.KeyConfirmed = true

			handshakeCompletion := session.multiplexer.ProtocolCompletion

			if !(handshakeCompletion.KeyConfirmed && handshakeCompletion.ClientHelloReceived) {
				log.Print("error: protocol handshake failed: one or more steps skipped")
				return shared.PacketProcessingDisconnect
			} else {
				log.Print("protocol established")
			}

			session.multiplexer.Ready.Store(true)

		} else {
			log.Print("error: unrecognized message type: ", signalpacket.MessageType)
			return shared.PacketProcessingSkipped
		}
		return shared.PacketProcessingOK

}

func (session *Session) ReorderSignalPackets(newPacket *shared.DecodedPacket, processFunc func(signalpacket *shared.SignalDecodedPacket) shared.PacketProcessingResult) {
	signalpacket := session.multiplexer.DecodedSignalPacket(newPacket)

	if signalpacket.SignalSequenceId < session.multiplexer.SignalExpectedSeqId.Load() {
		log.Print("warn: packet arrived too late")
		return
	}

	if signalpacket.SignalSequenceId > session.multiplexer.SignalExpectedSeqId.Load() + 500 {
		log.Print("warn: packet arrived way too early!")
		return
	}

	session.multiplexer.SignalUnorderedMu.Lock()
	defer session.multiplexer.SignalUnorderedMu.Unlock()

	session.multiplexer.SignalUnordered[signalpacket.SignalSequenceId] = signalpacket

	for {
		currentSequenceId := session.multiplexer.SignalExpectedSeqId.Add(1) - 1
		currentSignalPacket, exists := session.multiplexer.SignalUnordered[currentSequenceId]
		if !exists {
			log.Print("end of reorder chunk")
			return
		}

		result := processFunc(currentSignalPacket)
		if result == shared.PacketProcessingDisconnect {
			log.Print("disconnecting connection, as requested by signal processor")
			session.multiplexer.Disconnect()
		}
		delete(session.multiplexer.SignalUnordered, currentSequenceId)
	}

}

func (session *Session) HandleWebsocketLoop(conn *shared.WSStream) {

	log.Print("detected new websocket")

	session.clientsActive.Add(1)
	defer conn.Close()
	defer session.clientsActive.Add(-1)
	defer session.multiplexer.DeleteWebsocketStream(conn)
	defer func() {
		conn.SetReady(false)
	}()
	publicKey, privateKey, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		log.Print("error: failed to generate keypair", err)
		return
	}

	//server.WebsocketWriteMessage(conn, []byte{1}) // send READY status immediately

	for {
		_, rawMessage, err := conn.GetConnection().ReadMessage()
		if err != nil {
			log.Print("error: failed to read: ", err)
			return
		}
		decryptedMessage, err := conn.DecodeReadData(rawMessage)
		if err != nil {
			log.Print("error: failed to decode read message: ", err)
			continue
		}

		decodedPacket := session.multiplexer.DecodePacket(decryptedMessage)
		session.multiplexer.SendAcknowledged(decodedPacket.SequenceId)

		session.lastActiveTime = time.Now()

		if decodedPacket.MessageType == shared.MessageTypeNetwork {

			// is a network packet
			if (!conn.GetReady()) {
				log.Print("warn: ignored packet received during handshake")
				continue
			}

			if len(decodedPacket.Payload) < 2 {
				log.Print("error: message too short")
				continue
			}

			message := decodedPacket.Payload

			clientID := message[0]
			tcpConn, exists := session.clientIDs[int(clientID)]
			if err != nil {
				log.Print("error: failed to decrypt: ", err)
				continue
			}
			messagePayload := message[1:]
			if !exists {
				log.Print("unknown client id ", clientID, " attempting to dial")
				if len(messagePayload) < 5 {
					log.Print("message too short")
					continue
				}

				host, method, hostError := GetDialTarget(messagePayload[4:])
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

				tcpConnObj := shared.NewTCPStream(tcpConn)
				
				go session.HandleTCPConnection(tcpConnObj, conn, int(clientID))
				//log.Print("writing ", messagePayload)
				//tcpConn.Write(messagePayload)

				// tcpConnObj.ExpectedSequenceID.Add(1) // initial client packet, so add 1

				if isConnect {
					msgEstablished := []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
					// act as if the tcp connection sent this data
					session.limiterWait(session.outboundLimiter, len(msgEstablished))

					// ensure that the pending handshake data still goes somewhere
					// even if a websocket disconnects in the middle of all this logic

					// send it back

					// add seq id

				
					// log.Print("Send Websocket round robin and encrypting (initial established): ", base64.StdEncoding.EncodeToString(msgEstablished))
					// log.Printf("Sent message sum: %x\n", sha256.Sum256(msgEstablished))
					
					establishedMessageEncoded := tcpConnObj.EncodePacketPayload(clientID, msgEstablished)
					session.multiplexer.SendData(shared.MessageTypeNetwork, establishedMessageEncoded)		

					
				} else {

					// forward original handshake
					seqId, packetPayload := tcpConnObj.DecodePacketPayload(messagePayload)
					tcpConnObj.OnPacketReceived(packetPayload, seqId)

				}

				session.clientIDsMu.Lock()
				session.clientIDs[int(clientID)] = tcpConnObj
				session.clientIDsMu.Unlock()
			} else {
				// log.Print("received ", len(message)-2, " from websocket")

				// rate limiting
				session.limiterWait(session.outboundLimiter, len(messagePayload))
				
				seqId, packetPayload := tcpConn.DecodePacketPayload(messagePayload)
				tcpConn.OnPacketReceived(packetPayload, seqId)

			}
		} else if decodedPacket.MessageType == shared.MessageTypeReady              { session.ReorderSignalPackets(decodedPacket, session.ProcessSignalPacket) 
		} else if decodedPacket.MessageType == shared.MessageTypeAcknowledged       { session.ReorderSignalPackets(decodedPacket, session.ProcessSignalPacket) 
		} else if decodedPacket.MessageType == shared.MessageTypeClientHello        { session.ReorderSignalPackets(decodedPacket, session.ProcessSignalPacket)
		} else if decodedPacket.MessageType == shared.MessageTypeHandshake          { session.ReorderSignalPackets(decodedPacket, session.ProcessSignalPacket)
		} else if decodedPacket.MessageType == shared.MessageTypeTCPAcknowledged    { session.ReorderSignalPackets(decodedPacket, session.ProcessSignalPacket)
		} else if decodedPacket.MessageType == shared.MessageTypeSignalAcknowledged { session.ReorderSignalPackets(decodedPacket, session.ProcessSignalPacket)
		} else if decodedPacket.MessageType == shared.MessageTypeSignature          { session.ReorderSignalPackets(decodedPacket, session.ProcessSignalPacket)
		} else if decodedPacket.MessageType == shared.MessageTypeAcknowledged       { session.ReorderSignalPackets(decodedPacket, session.ProcessSignalPacket)
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

func (server *Server) marshalSessionCreationResponse(ok bool, message string, sessionId *int, identityToken *string) string {
	res := SessionCreationResponse{Ok: ok, SessionId: sessionId, IdentityToken: identityToken, Message: message}
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
		fmt.Fprintln(w, server.marshalSessionCreationResponse(false, "Invalid proof of work token or solution", nil, nil))
		return
	}

	attempts := 0
	for {
		sessionId, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
		if err != nil {
			log.Print("error: failed to generate a random number lol")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, server.marshalSessionCreationResponse(false, "Failed to create session", nil, nil))
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
					fmt.Fprintln(w, server.marshalSessionCreationResponse(false, "Too many active sessions. Cannot create a new session.", nil, nil))
					return
				}
				continue
			}

			identityToken, err := server.identityProvider.CreateIdentityToken(int(sessionId.Int64()))
			if err != nil {
				log.Print("error: failed to create identity token: ", err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, server.marshalSessionCreationResponse(false, "Failed to issue an identity token", nil, nil))
				return
			}

			session := NewSession()
			server.sessionsMu.Lock()
			server.sessions[int(sessionId.Int64())] = session
			server.sessionsMu.Unlock()
			w.WriteHeader(http.StatusOK)
			sessionIdInt := int(sessionId.Int64())
			log.Print("creating session id: ", sessionIdInt)
			fmt.Fprintln(w, server.marshalSessionCreationResponse(true, "OK", &sessionIdInt, &identityToken))

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

	session.multiplexer.StreamsMu.RLock()
	numberOfStreams := len(session.multiplexer.Streams)
	session.multiplexer.StreamsMu.RUnlock()


	if numberOfStreams >= 8 {
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


	connectionObject := session.multiplexer.NewWebsocketStream(conn)

	session.multiplexer.AddWebsocketStream(connectionObject)

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
