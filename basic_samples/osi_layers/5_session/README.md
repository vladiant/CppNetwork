# OSI Layer 5 - Session Layer

A small C++17 / CMake demo for Linux that

1. prints reference information about the OSI **Session Layer** (Layer 5),
   with detailed write-ups for **NetBIOS**, **RPC**, and **SOCKS** plus
   the canonical X.225 / ISO 8327 session-establishment phases, and
2. **listens** on the standard session-layer ports and parses incoming
   traffic for those protocols (with brief logging for the rest).

## Layout

```
5_session/
├── CMakeLists.txt
├── README.md
├── include/
│   ├── listener.hpp
│   └── session_layer.hpp
└── src/
    ├── listener.cpp
    ├── main.cpp
    └── session_layer.cpp
```

## Build (Linux)

```bash
cd 5_session
cmake -S . -B build
cmake --build build -j
```

The binary is produced at `build/session_layer`.

## Run

### Information modes

```bash
./build/session_layer                 # full report (default)
./build/session_layer --overview      # role of the session layer
./build/session_layer --establishment # session establishment phases
./build/session_layer --netbios       # detailed NetBIOS
./build/session_layer --rpc           # detailed RPC
./build/session_layer --socks         # detailed SOCKS
./build/session_layer --list          # brief list of all protocols
./build/session_layer --help
```

### Listener mode

`--listen` binds the TCP/UDP sockets below and prints every accepted
connection / received datagram, parsing the first bytes for the
detailed protocols:

| Proto           | Transport | Port | Parser |
|-----------------|-----------|------|--------|
| NetBIOS-NS      | UDP       | 137  | yes (NBNS query/response, decoded name) |
| NetBIOS-DGM     | UDP       | 138  | yes (logs hex preview) |
| NetBIOS-SSN     | TCP       | 139  | yes (NBT type, length, called name on SESSION REQUEST) |
| Sun-RPC portmap | TCP       | 111  | yes (DCE/RPC-style header) |
| MS-RPC          | TCP       | 135  | yes (DCE/RPC ptype: BIND, BIND_ACK, REQUEST, …) |
| SOCKS           | TCP       | 1080 | yes (SOCKS4 request, SOCKS5 greeting + auth methods) |
| SMB             | TCP       | 445  | yes (SMB1 / SMB2/3 magic detection) |
| PPTP            | TCP       | 1723 | logged only |
| L2TP            | UDP       | 1701 | logged only |
| H.323 Q.931     | TCP       | 1720 | logged only |

Ports below 1024 are privileged on Linux. Either run as root:

```bash
sudo ./build/session_layer --listen
```

or grant the binary `CAP_NET_BIND_SERVICE` once:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./build/session_layer
./build/session_layer --listen
```

Ports already used by another service are reported and skipped; the
listener still runs on whatever it could bind. Press **Ctrl+C** to
stop. To see what will be tried without binding:

```bash
./build/session_layer --ports
```

#### Quick test

In one terminal:

```bash
sudo ./build/session_layer --listen
```

In another:

```bash
# SOCKS5 greeting (no-auth + user/pass)
printf '\x05\x02\x00\x02' | nc -q1 127.0.0.1 1080

# NBT session request (truncated)
printf '\x81\x00\x00\x44' | nc -q1 127.0.0.1 139
```

Each will produce a timestamped, parsed line in the listener's output.

## What the program covers

### Detailed protocols
- **NetBIOS** — name (UDP/137), datagram (UDP/138) and session
  (TCP/139) services; NBT session-establishment PDUs
  (SESSION REQUEST / POSITIVE / NEGATIVE SESSION RESPONSE).
- **RPC** — ONC RPC (portmapper on 111), DCE/RPC and MS-RPC
  (endpoint mapper on 135); CALL/REPLY messages and DCE BIND/BIND_ACK.
- **SOCKS** — SOCKS4/4a/5 (RFC 1928) on TCP/1080; greeting,
  authentication negotiation, CONNECT/BIND/UDP ASSOCIATE request and
  reply formats.

### Session establishment (X.225 / ISO 8327)
1. Connection Request (CN SPDU)
2. Parameter Negotiation (functional units, tokens)
3. Connection Confirmation (AC SPDU)
4. Data Transfer / Dialog Control
5. Synchronization & Checkpointing (minor/major sync points)
6. Activity Management
7. Orderly Release (FN / DN SPDUs)
8. Abort (AB SPDU)

### Other protocols (brief)
PPTP, L2TP, SMB, SDP, AppleTalk ASP, ITU-T H.245, ISO 8327 / X.225.

## Requirements
- Linux
- CMake ≥ 3.16
- A C++17-capable compiler (GCC ≥ 7 or Clang ≥ 5)
