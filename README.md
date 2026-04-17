# net-tunnel

Lightweight encrypted tunnel for browsing

> [!WARNING]
> Very experimental

## Features

- Encryption
- Zero interruption
- Obfuscation
- Multiplexing
- Message reliability across sessions
- and some other things

## Protocol

**Message layout**:

```
MXSEQID: multiplexer sequencer ID
MSGSIZE: message size
TYP: type
PAYLOAD: payload
SIGSEQID: signal sequencer ID
TCPSEQID: tcp stream sequencer id
SID: logical tcp stream id

layout examples:

----external--------|----internal-------
MXSEQID TYP MSGSIZE  SIGSEQID PAYLOAD...
0 0 0 4  9  0 0 0 8  0 0 0 4  0 0 0 3

----external--------|---internal---------
MXSEQID  TYP MSG SIZE SID TCPSIGID  PAYLOAD...
0 0 0 82  0  0 0 0 44 70  0 0 0  0  72 84 84 80 47 49 46 49 32 50 48 48 32 67 111 110 110 101 99 116 105 111 110 32 69 115 116 97 98 108 105 115 104 101 100 13 10 13 10
```

see protocol.md for more info
