# OSI Application Layer Sniffer (Layer 7)

A modern C++20 packet capture tool that reads frames from a network interface
and surfaces a human-readable view of the most common **OSI Layer 7 / Application
Layer** protocols:

| Protocol | Transport | Default ports detected | Notes |
|----------|-----------|------------------------|-------|
| **HTTP/1.x** | TCP | 80, 8000, 8008, 8080, 8888 | Method, path, status line, `Host:` header |
| **HTTP/2 (h2c)** | TCP | 80, 443, 8080, 8443 | Client preface + frame type/length/flags/stream id |
| **QUIC**     | UDP | 443, 80, 8443 | Long-header packets: version, packet type, DCID length |
| **DNS**      | UDP | 53, 5353 (mDNS), 5355 (LLMNR) | Opcode, rcode, first question name + qtype |
| **TLS**      | TCP | 443, 465, 587, 636, 853, 993, 995, 8443… | Record type, version, ClientHello SNI |
| **SMTP**     | TCP | 25, 465, 587, 2525 | Commands (`HELO/EHLO/MAIL/RCPT/...`) and 3-digit replies |
| **MQTT**     | TCP | 1883, 8883 | Packet type, flags, `CONNECT` proto name, `PUBLISH` topic & QoS |
| **RTP**      | UDP | dynamic ≥1024 | Heuristic: v=2 + known/dynamic payload type, seq/ts/SSRC |

> Note: traffic carried inside TLS (HTTPS, HTTP/2 over TLS, secure SMTP, MQTT/TLS,
> SRTP, …) is encrypted on the wire and only the TLS handshake/record metadata
> is visible.

## Requirements

* Linux
* C++20 compiler (GCC ≥ 11 or Clang ≥ 13)
* CMake ≥ 3.16
* `libpcap` development headers

Install dependencies:

```bash
# Debian / Ubuntu
sudo apt-get install build-essential cmake libpcap-dev

# Fedora / RHEL
sudo dnf install gcc-c++ cmake libpcap-devel

# Arch
sudo pacman -S base-devel cmake libpcap
```

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The binary is `build/app_layer_sniffer`.

## Run

Packet capture requires elevated privileges. Either run with `sudo`, or grant
the binary the necessary capabilities once and run it as a normal user:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./build/app_layer_sniffer
./build/app_layer_sniffer -i lo
```

### Examples

```bash
# Auto-pick first interface
sudo ./build/app_layer_sniffer

# Capture on a specific interface
sudo ./build/app_layer_sniffer -i wlan0

# Restrict capture to a host with an extra BPF filter
sudo ./build/app_layer_sniffer -i eth0 -f "host 1.1.1.1"

# Loopback testing (e.g. against a local HTTP/MQTT/SMTP server)
sudo ./build/app_layer_sniffer -i lo
```

### CLI options

```
-i, --interface <name>   Network interface (default: auto-pick first)
-f, --filter   <expr>    Extra BPF filter (e.g. "tcp port 1883")
-s, --snaplen  <bytes>   Snapshot length (default 65535)
    --no-promisc         Disable promiscuous mode
-h, --help               Show usage
```

### Sample output

```
[14:02:11.184302] DNS    192.168.1.10:54321 -> 1.1.1.1:53        QUERY id=0xab12 op=QUERY qd=1 an=0  q=example.com/A
[14:02:11.205117] DNS    1.1.1.1:53 -> 192.168.1.10:54321        RESP id=0xab12 op=QUERY rcode=NOERROR qd=1 an=1  q=example.com/A
[14:02:11.221908] TLS    192.168.1.10:50112 -> 93.184.216.34:443 Handshake TLS1.0 len=512 ClientHello ver=TLS1.2 SNI=example.com
[14:02:11.260441] HTTP   192.168.1.10:55014 -> 93.184.216.34:80  REQ  GET /index.html HTTP/1.1  (Host:example.com)
[14:02:11.270880] HTTP   93.184.216.34:80 -> 192.168.1.10:55014  RESP HTTP/1.1 200 OK
[14:02:11.305210] QUIC   192.168.1.10:51234 -> 142.250.190.46:443 v=0x00000001 type=Initial dcid_len=8
[14:02:12.118233] MQTT   192.168.1.10:33422 -> 192.168.1.30:1883 CONNECT flags=0x0 remaining=14 proto="MQTT" level=4
[14:02:12.118994] MQTT   192.168.1.10:33422 -> 192.168.1.30:1883 PUBLISH flags=0x0 remaining=21 qos=0 topic="sensors/temp"
[14:02:13.001210] SMTP   10.0.0.5:46110 -> 10.0.0.20:25          C: EHLO mail.example.org
[14:02:13.001995] SMTP   10.0.0.20:25 -> 10.0.0.5:46110          S: 250-mail.example.org Hello
[14:02:14.220011] RTP    10.0.0.5:5004 -> 10.0.0.6:5004           PT=0(PCMU) seq=21456 ts=320000 ssrc=0xdeadbeef marker=0 cc=0
```

## Project layout

```
.
├── CMakeLists.txt
├── README.md
└── src
    ├── main.cpp              # CLI + signal handling
    ├── packet.hpp            # PacketView and parser entry points
    ├── sniffer.hpp/.cpp      # libpcap loop, link/IP/L4 decoding, dispatch
    └── parsers/
        ├── http.cpp          # HTTP/1.x request/response detection
        ├── http2.cpp         # HTTP/2 cleartext (h2c) frames + preface
        ├── quic.cpp          # QUIC long-header packet parsing
        ├── dns.cpp           # DNS header + first question (with QNAME compression)
        ├── tls.cpp           # TLS record + ClientHello SNI extraction
        ├── smtp.cpp          # SMTP commands & numeric responses
        ├── mqtt.cpp          # MQTT control packets, CONNECT/PUBLISH details
        └── rtp.cpp           # RTP heuristic detection (v2 + payload type)
```

## How it works

1. `Sniffer` opens a libpcap handle on the chosen interface in promiscuous +
   immediate mode.
2. Each captured frame is parsed top-down through the OSI stack:
   - **L2** Ethernet, with optional VLAN tags, or `LINUX_SLL`/`LINUX_SLL2`
     pseudo-headers (used by the `any` interface).
   - **L3** IPv4 or IPv6 (a couple of common IPv6 extension headers are walked).
   - **L4** TCP or UDP — header length is honoured, the resulting payload is
     handed to the dispatcher as a `std::span<const std::uint8_t>`.
3. The dispatcher tries each application-layer parser in turn (most specific
   first). The first parser that recognizes the payload prints a one-line
   summary and the packet is consumed.

All parsers are bounds-checked and treat captured bytes as untrusted input.

## Limitations

* TCP **reassembly** is not performed. A protocol message split across multiple
  segments will only be parsed if the relevant header fits in a single segment.
* TLS-encrypted application data is opaque; only handshake/record metadata is
  surfaced.
* RTP detection is heuristic. A BPF filter such as `udp portrange 16384-32767`
  greatly improves precision in real environments.
* IPv6 fragmentation and uncommon extension headers are not handled.

## License

This sample is provided for educational purposes as part of the
`CppNetwork/basic_samples/osi_layers` series.
