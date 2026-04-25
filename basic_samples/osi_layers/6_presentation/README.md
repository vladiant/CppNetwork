# OSI Layer 6 — Presentation Layer Demo

A small C++17 / CMake project for Linux that illustrates the four classic
responsibilities of the OSI **Presentation Layer**:

| Responsibility | Demo                                                    |
| -------------- | ------------------------------------------------------- |
| Encoding       | ASCII vs UTF-8 byte view + Base64 round-trip (OpenSSL)  |
| Compression    | DEFLATE compression at levels 1 / 6 / 9 (zlib)          |
| TLS encryption | OpenSSL version, TLS 1.2/1.3 protocol range and ciphers |
| SSL encryption | Legacy SSL 2.0 / 3.0 status & deprecation notes         |

The Presentation Layer (Layer 6) sits between the Application and Session
layers. It translates between the data formats used by applications and the
formats sent over the network — character set conversion, serialization,
compression and encryption all live here.

## Requirements

- Linux
- A C++17 compiler (GCC ≥ 7 or Clang ≥ 6)
- CMake ≥ 3.16
- OpenSSL development headers
- zlib development headers

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev zlib1g-dev
```

On Fedora:

```bash
sudo dnf install gcc-c++ cmake openssl-devel zlib-devel
```

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Run

Run the local demonstrations:

```bash
./build/presentation_layer_demo
```

### TLS listener mode

The program can also act as a single-shot TLS listener bound to
`127.0.0.1`. It generates a self-signed RSA-2048 certificate **in memory**
(no files written), accepts one TLS client, prints the negotiated protocol
and cipher, and then reports presentation-layer details (hex dump, Base64,
zlib compression ratio) for the first record received from the peer.

```bash
# Terminal 1 - start the listener (default port 4443)
./build/presentation_layer_demo --listen 4443

# Terminal 2 - connect with any TLS client
printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' \
  | openssl s_client -connect 127.0.0.1:4443 -quiet
```

Sample listener output:

```
=== Presentation Layer TLS Listener ===
Generating in-memory self-signed certificate...
Listening on 127.0.0.1:4443 (waiting for one TLS client)

Accepted TCP from 127.0.0.1:35584
TLS handshake OK
  protocol     : TLSv1.3
  cipher       : TLS_AES_256_GCM_SHA384 (256 bits)

Reading first record from peer...
  bytes        : 35
  as text      : "GET / HTTP/1.0"
  hex (first 32 B): 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 30 0d 0a ...
  base64       : R0VUIC8gSFRUUC8xLjANCkhvc3Q6IGxvY2FsaG9zdA0KDQo=
  zlib size    : 41 B (ratio 117.143%)
```

Because the certificate is self-signed, clients must skip verification
(`openssl s_client` does so by default; browsers will warn). SSL 2.0/3.0
are intentionally not offered — the listener restricts itself to TLS 1.2
and TLS 1.3.

## Sample output (abridged)

```
############################################
#  OSI Layer 6 - Presentation Layer Demo  #
############################################

=== Encoding (character set & binary-to-text) ===
ASCII string : "Hello, OSI!" (11 bytes)
UTF-8 string : "Héllo, OSI — Καλημέρα 🌐" (32 bytes)
UTF-8 hex    : 48 c3 a9 6c 6c 6f 2c 20 4f 53 49 20 ...
Base64       : SMOpbGxvLCBPU0kg4oCUIM6a4Z...
Round-trip   : "Héllo, OSI — Καλημέρα 🌐" [OK]

=== Compression (zlib / DEFLATE) ===
zlib version : 1.2.13
  level=1  original=2900 B  compressed=...  ratio=...
  level=6  original=2900 B  compressed=...  ratio=...
  level=9  original=2900 B  compressed=...  ratio=...

=== TLS (Transport Layer Security) ===
OpenSSL      : OpenSSL 3.0.x ...
Min protocol : TLS 1.2
Max protocol : TLS 1.3
Cipher suites: N available
  - TLS_AES_256_GCM_SHA384  (TLSv1.3, 256 bits)
  ...

=== SSL (legacy Secure Sockets Layer) ===
Protocol     Status        Notes
  SSL 2.0    unavailable   removed; broken cryptography
  SSL 3.0    unavailable   removed; vulnerable to POODLE
  TLS 1.0    deprecated    deprecated by RFC 8996
  TLS 1.1    deprecated    deprecated by RFC 8996
  TLS 1.2    supported     widely supported
  TLS 1.3    supported     current best practice (RFC 8446)
```

## Project layout

```
6_presentation/
├── CMakeLists.txt
├── README.md
└── src/
    ├── main.cpp
    ├── encoding.{h,cpp}      # Base64 / UTF-8 / ASCII
    ├── compression.{h,cpp}   # zlib DEFLATE
    ├── tls_info.{h,cpp}      # TLS protocol and cipher listing
    ├── ssl_info.{h,cpp}      # Legacy SSL status table
    └── listener.{h,cpp}      # Single-shot TLS server (self-signed cert)
```

## Notes

- This demo only **inspects** the local TLS/SSL stack — it does not open a
  network connection. The cipher list reflects what the linked OpenSSL build
  supports as a client.
- SSL 2.0 and SSL 3.0 are intentionally not exercised: modern OpenSSL builds
  remove them entirely. They are listed only for educational completeness.
