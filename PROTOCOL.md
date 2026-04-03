# The New Protocol

**Multistreamed protocol, reliable, zero-interruption abstracted custom protocol**

Extremely complicated to wrap your head around.
Attempts to document everything NEW to the protocol (the new reliability-first architecture)

## Enveloppes

**Websocket Enveloppe*:

```
Multiplexer Sequence ID: 4 bytes (big endian unsigned int 32 bits):
 - Global sequence ID for the entire Multiplexer object, allowing for the retransmission
   of dropped packets.
Message Type: 1 byte
 - Distinguises between different message types
Payload Size: 4 bytes (big endian unsigned int 32 bits)
 - Allows the actual packet size to vary, allowing for advanced techniques that involve
   manipulating packet sizes to bypass deep packet inspection from firewalls.
Payload: The actual payload
```

**TCP Stream Enveloppe**

This is inside the payload of the previous Websocket enveloppe.

```
TCP Stream Sequence ID: 4 bytes (big endian unsigned int 32 bits)
 - Allows for the reordering of packets arrived at different times.
Payload: the data
```

**SIGNAL Stream Enveloppe**

Conceptually the same as TCP stream enveloppe

```
SIGNAL Stream Sequence ID: 4 bytes (big endian unsigned int 32 bits)
 - Allows for the reordering of signal packets (although not strictly required)
Payload: data
```

## Sequence IDs

**Multiplexer Sequence ID**

Does not perform reordering. Instead, it provides a way for both parties to track which packets have been sent successfully
and which need retransmission. If a WebSocket stream disconnects while sending a packet, or is marked unhealthy by the
connection health checker, all packets that have not been acknowledged by the server must be retransmitted. Packets with the
same sequence ID received twice are ignored.

**TCP Stream Sequence ID**

Performs reordering, guarantees order for the recipient (the browser). Each stream has a different sequence ID, allowing for
efficient multiplexing and eliminating Head of Line blocking (HoL).

**SIGNAL Stream Sequence ID**

Global, per multiplexer, sequence ID. Performs reordering for signal packets.

## Health Checker

(Not implemented yet)

The health checker consitently performs a latency check (ping/pong) to determine if a connection is being throttled by a firewall or
by deep packet inspection heuristics. If detected, the connection will be marked as unhealthy and will be killed. A new connection
will be established by the client.

## Full Disconnect

(Not implemented yet)

If all Websockets were to fully disconnect, the client will queue the packets for retransmission, but will also queue all packets that
were supposed to be sent at that time. When a connection becomes available, queued packets will be retransmitted to the server, allowing
almost zero interruption.

## Rotation

(Not implemented yet)

A job on the client will constantly kill a Websocket after around 10-20 seconds after being ready. This significantly decreases the ability
for a deep packet inspection firewall to correlate activity long-term on a single connection, therefore increasing reliability substantially.
It will be unoticeable for the user, as connections will not be killed at the exact same time, always leaving at least one connection for
streaming.

## Round Robin Packets

Packets are sent in a round-robin method, making the DPI having a harder time to correlate, since one stream represents multiple TCP connections.
Everything is abstracted and WebSockets are simply pipes to forward data, with almost no linked state.

## Encryption

Performs strong encryption on the data to ensure obscurity to deep packet inspection firewalls.

## Packet Timing & Packet Size Normalization

(Future Feature)

Ensures all packets are the same size and chunked, using the abstracted multiplexer architecture.
Increases reliability on deep packet inspection networks.
