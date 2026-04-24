# datalink_reader

A small **C++20** sample that captures and parses OSI **Layer 2 (Data Link
Layer)** frames on Linux using raw `AF_PACKET` sockets.

---

## How it works

| Stage | What the code does |
|---|---|
| **Socket creation** | `AF_PACKET` + `SOCK_RAW` + `ETH_P_ALL` — bypasses the network stack and receives every Ethernet frame on the wire |
| **Interface binding** | `ioctl(SIOCGIFINDEX)` + `bind(sockaddr_ll)` to pin to a specific NIC |
| **Frame parsing** | Decodes the Ethernet II header (dst MAC, src MAC, EtherType) and handles **802.1Q VLAN** and **802.1ad QinQ** tags |
| **Payload dump** | Prints the first 64 bytes of the frame payload as hex |
| **Shutdown** | `SIGINT` / `SIGTERM` flip a `std::atomic<bool>` so the capture loop exits cleanly |

### Modern C++ touches

- `std::span<const std::uint8_t>` for zero-copy byte views into the parser and
  hex-dumper (no raw `(ptr, len)` pairs).
- `std::optional<EthernetFrame>` return from the parser instead of an
  out-parameter + `bool`.
- `std::bit_cast` at the `sockaddr` boundary in place of `reinterpret_cast`.
- Unaligned big-endian reads go through a `std::memcpy`-based `read_be16`
  helper (avoids UB on strict-alignment targets).
- RAII `UniqueFd` wrapper ensures the socket is closed on every exit path.
- `std::atomic<bool>` signal flag with an `extern "C"` handler.

---

## Requirements

- Linux (raw `AF_PACKET` sockets are Linux-specific)
- A C++20 compiler (GCC 10+, Clang 11+)
- CMake ≥ 3.20
- Root privileges **or** `CAP_NET_RAW` on the built binary

---

## Build & run

```bash
# Configure & build
cmake -S . -B build
cmake --build build

# Run (root or CAP_NET_RAW required for raw sockets)
sudo ./build/datalink_reader eth0   # replace eth0 with your interface, e.g. ens3, wlan0

# Or grant the capability once to avoid sudo:
sudo setcap cap_net_raw+ep ./build/datalink_reader
./build/datalink_reader eth0
```

If no interface is given on the command line, the program defaults to `eth0`.

> **Find your interface name:** run `ip link show` or `ls /sys/class/net/`.

---

## Sample output

```
OSI Layer 2 - Data Link Frame Reader
Interface : eth0
Press Ctrl+C to stop.

┌─ Frame #1 ─────────────────────────────────────────
│ Dst MAC   : FF:FF:FF:FF:FF:FF
│ Src MAC   : 00:1A:2B:3C:4D:5E
│ EtherType : 0x0806  (ARP)
│ Total len : 42 bytes   Payload: 28 bytes
│ Payload (hex, first 64 bytes):
    0000  00 01 08 00 06 04 00 01 00 1a 2b 3c 4d 5e c0 a8
    0010  01 01 00 00 00 00 00 00 c0 a8 01 fe
└─────────────────────────────────────────────────────
```

VLAN-tagged frames get an extra line:

```
│ VLAN      : id=100  priority=0
```

---

## Files

- [main.cpp](main.cpp) — capture loop, parser, and pretty-printer
- [CMakeLists.txt](CMakeLists.txt) — C++20 build configuration
