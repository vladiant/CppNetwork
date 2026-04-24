# OSI Layer 4 — Transport Layer Sniffer

A small Linux/C++17 CMake project that opens raw IP sockets, reads packets from
the kernel, and decodes the **OSI Transport Layer** (Layer 4) headers.

It produces a detailed decode for the most common transport protocols and a
basic summary for everything else.

## What is the Transport Layer?

OSI Layer 4 lives between the Network layer (L3 — IP) and the Session layer (L5).
Its job is to deliver data **between processes** identified by **ports**, with
guarantees that depend on the protocol:

| Property            | TCP                | UDP            | SCTP                          | QUIC                          |
|---------------------|--------------------|----------------|-------------------------------|-------------------------------|
| IANA proto number   | 6                  | 17             | 132                           | 17 (runs over UDP)            |
| Connection-oriented | yes                | no             | yes (associations)            | yes                           |
| Reliable            | yes                | no             | yes (configurable)            | yes                           |
| Ordering            | byte stream        | none           | per-stream                    | per-stream                    |
| Message boundaries  | no (stream)        | yes            | yes                           | yes (frames over streams)     |
| Multi-streaming     | no                 | no             | yes                           | yes                           |
| Multi-homing        | no                 | no             | yes                           | connection migration          |
| Flow control        | sliding window     | none           | rwnd + per-stream             | MAX_DATA / MAX_STREAM_DATA    |
| Congestion control  | yes (Reno/Cubic/…) | no             | yes                           | yes (CUBIC/BBR, pluggable)    |
| Built-in security   | no (TLS on top)    | no (DTLS opt.) | no                            | yes (TLS 1.3 integrated)      |

### Ports

Both TCP, UDP and SCTP carry a 16-bit **source port** and a 16-bit
**destination port**. IANA splits the 0–65535 range into:

* **Well-known**: 0–1023 (e.g. 22 SSH, 53 DNS, 80 HTTP, 443 HTTPS/QUIC).
* **Registered**: 1024–49151.
* **Dynamic / ephemeral**: 49152–65535.

This sniffer prints a friendly name for common ports.

### Flow control vs. congestion control

* **Flow control** keeps a fast sender from overwhelming a slow *receiver*
  (TCP advertised window, SCTP `a_rwnd`, QUIC `MAX_DATA`/`MAX_STREAM_DATA`).
* **Congestion control** keeps a sender from overwhelming the *network*
  (TCP/SCTP/QUIC all implement it; UDP does not).

This tool reports the per-packet flow-control field where applicable
(TCP advertised window, SCTP verification tag/SACK presence, QUIC long/short
header form).

## What this tool decodes

* **TCP** — ports, sequence/ack numbers, header length, control flags
  (SYN/ACK/FIN/RST/PSH/URG/ECE/CWR), advertised window (flow control), checksum.
* **UDP** — ports, length, checksum. Notes that UDP itself has no flow control.
* **QUIC** — heuristically detected on UDP/443: prints first byte (long/short
  header form, fixed bit) and version, and notes that QUIC implements
  reliability, multiplexed streams, and stream/connection-level flow control.
* **SCTP** — common header (ports, verification tag, CRC32c checksum) and the
  first few chunk types (INIT, DATA, SACK, HEARTBEAT, …).
* **Other L4 protocols** (ICMP, ICMPv6, GRE, ESP, AH, DCCP, UDP-Lite, IGMP,
  PIM, OSPF-in-IP, etc.) — IANA name and payload size.

Both IPv4 and IPv6 are handled.

## Build

```bash
cd 4_transport
cmake -S . -B build
cmake --build build -j
```

Produces `build/transport_sniffer`.

## Run

The sniffer uses an `AF_PACKET` socket (same mechanism as `tcpdump`), which
requires `CAP_NET_RAW`:

```bash
# Easiest — run as root:
sudo ./build/transport_sniffer

# Or grant the capability once and run unprivileged:
sudo setcap cap_net_raw=eip ./build/transport_sniffer
./build/transport_sniffer

# Bind to a specific interface (recommended — e.g. your main NIC or `lo`):
sudo ./build/transport_sniffer -i eth0
sudo ./build/transport_sniffer -i lo

# Capture only N packets then exit:
sudo ./build/transport_sniffer -n 20
sudo ./build/transport_sniffer -i wlan0 -n 50
```

> **Note:** A raw IPv4 socket opened with `IPPROTO_RAW` is **send-only** on
> Linux — the kernel does not deliver received packets to it. That is why
> this tool uses `AF_PACKET` with `ETH_P_ALL`, which captures every incoming
> and outgoing frame and then strips the Ethernet header before decoding L3/L4.

Generate some traffic in another terminal to see output, e.g.:

```bash
curl https://example.com         # TCP + (often) QUIC
dig @1.1.1.1 example.com         # UDP/53
ping -c 3 1.1.1.1                # ICMP (basic info)
```

## Sample output

```
IPv4 192.168.1.10 -> 93.184.216.34 | proto=6 (TCP) | total=60B
  [TCP] Transmission Control Protocol (connection-oriented, reliable)
        Src port : 51324
        Dst port : 443 (HTTPS / QUIC)
        Seq      : 2487163920
        Ack      : 0
        Hdr len  : 40 bytes
        Flags    : SYN
        Flow ctl : sliding-window, advertised window = 64240 bytes
        Checksum : 0xa1f3
----
IPv4 192.168.1.10 -> 1.1.1.1 | proto=17 (UDP) | total=73B
  [UDP] User Datagram Protocol (connectionless, unreliable)
        Src port : 50211
        Dst port : 53 (DNS)
        Length   : 53 bytes
        Checksum : 0x4c2a
        Flow ctl : none at UDP layer (application-defined)
----
```

## Project layout

```
4_transport/
├── CMakeLists.txt
├── README.md
└── src/
    ├── main.cpp                  # Entry point: open raw sockets, poll, dispatch
    ├── transport_sniffer.hpp     # Public decode API
    └── transport_sniffer.cpp     # TCP/UDP/SCTP/QUIC + generic L4 decoders
```

## Limitations

* Raw IP sockets receive packets **after** the kernel has processed them; this
  is not a substitute for `libpcap`/AF_PACKET. For full packet capture
  (including link layer and outgoing frames) use Wireshark/tcpdump.
* QUIC detection is heuristic (UDP/443 + QUIC fixed bit). Encrypted payload
  contents are not parsed.
* Linux-only (uses `<netinet/*.h>` and `SOCK_RAW`).

## License

Sample/educational code. Use freely.
