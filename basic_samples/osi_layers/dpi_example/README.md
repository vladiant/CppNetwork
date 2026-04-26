# DPI Example

A minimal **Deep Packet Inspection (DPI)** demo in modern C++ (C++20). It
captures raw Ethernet frames on Linux, walks the OSI stack
(L2 → L3 → L4 → L7), tracks per-flow state by the classic 5-tuple, and
runs a tiny payload classifier that recognizes **HTTP** and **TLS**.

This sample is part of the `osi_layers` series and focuses on the
*application-layer inspection* idea: looking past headers into the payload
of established TCP flows.

## What it does

- Opens an `AF_PACKET` / `SOCK_RAW` socket bound to `ETH_P_ALL`.
- Parses each frame:
  - **L2**: Ethernet, with optional 802.1Q VLAN tag.
  - **L3**: IPv4 only (skips ARP, IPv6, etc.). Validates `ihl`,
    `version`, `tot_len`.
  - **L4**: TCP only. Validates `doff`, computes payload offset/length.
- Maintains a `std::unordered_map<FlowKey, FlowState>` keyed by
  `(src_ip, dst_ip, src_port, dst_port, protocol)`.
- Classifies the L7 protocol on the first non-empty payload of a flow:
  - **TLS** — record header `0x16 0x03 0x0{1..4}` (Handshake, TLS 1.0–1.3).
  - **HTTP** — request methods (`GET`, `POST`, `HEAD`, …) or `HTTP/1.` response.
- Logs new flows and L7 transitions in real time, prints a summary on exit.

## Project layout

```
dpi_example/
├── CMakeLists.txt
├── main.cpp        # all the code lives here
└── README.md
```

Key types in [main.cpp](main.cpp):

- `FlowKey` / `FlowKeyHash` — 5-tuple key with a golden-ratio hash mix.
- `FlowState` — per-flow counters + `L7Protocol` plus `classify()`.
- `parse_packet()` — bounds-checked Ethernet/IPv4/TCP parser.
- `run_capture()` — capture loop with clean `SIGINT` / `SIGTERM` shutdown.

## Requirements

- Linux (uses `AF_PACKET`, `linux/if_ether.h`, `linux/if_packet.h`).
- A C++20 compiler (GCC ≥ 10, Clang ≥ 12).
- CMake ≥ 3.20, Ninja or Make.
- `CAP_NET_RAW` to open the raw socket (root or `setcap`).

## Build

```sh
cmake -S . -B build -G Ninja
cmake --build build
```

The resulting binary is `build/dpi_example`.

## Run

The program needs `CAP_NET_RAW`. Either run as root:

```sh
sudo ./build/dpi_example
```

…or grant the capability once and run unprivileged:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip ./build/dpi_example
./build/dpi_example
```

Stop with `Ctrl+C`. Example output:

```
DPI capture started. Press Ctrl+C to stop.
[flow]       192.168.1.20:54231 -> 142.250.74.110:443   L7=Unknown
[classified] 192.168.1.20:54231 -> 142.250.74.110:443   L7=TLS
[flow]       192.168.1.20:54232 -> 93.184.216.34:80     L7=Unknown
[classified] 192.168.1.20:54232 -> 93.184.216.34:80     L7=HTTP
^C
--- Capture summary ---
packets seen   : 1432
TCP/IPv4 parsed: 1187
flows tracked  : 24

192.168.1.20:54231     -> 142.250.74.110:443      pkts=  84 bytes=  61234 L7=TLS
192.168.1.20:54232     -> 93.184.216.34:80        pkts=  12 bytes=    854 L7=HTTP
...
```

## Generating traffic for a quick demo

In another terminal, while the capture is running:

```sh
curl http://example.com/             # produces an HTTP flow
curl https://example.com/            # produces a TLS flow
```

## Limitations

This is intentionally small and meant to illustrate the DPI pipeline,
not be a production tool:

- IPv4 + TCP only; no IPv6, UDP, QUIC, GRE, IP fragmentation, or
  TCP segment reassembly.
- L7 classification is byte-pattern based (no SNI extraction, no
  HTTP header parsing).
- The flow table is unbounded and never aged — long captures grow memory.
- `g_flow_table` is single-threaded; no locking.
- Each `recv()` returns one frame; no `PACKET_MMAP` ring buffer.

## License

Provided as an educational sample. Use freely.
