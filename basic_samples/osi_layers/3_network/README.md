# network_layer_reader

---

## Architecture overview

```
AF_PACKET raw socket  (Layer 2)
        │
        ▼
dispatch_ethernet()       — strips Ethernet / 802.1Q VLAN header, routes by EtherType
        │
        ├─ EtherType 0x0800 ──► decode_ipv4()
        │                           • IHL / TOS / DSCP / ECN
        │                           • ID, DF/MF flags, fragment offset  ← fragmentation
        │                           • TTL (routing/forwarding metric)
        │                           • IPv4 options (RR, TS, LSRR, SSRR…) ← routing
        │                           └─► decode_icmpv4()  or  print_upper_layer_summary()
        │
        └─ EtherType 0x86DD ──► decode_ipv6()
                                    • Traffic Class / DSCP / ECN
                                    • Flow Label
                                    • Hop Limit  (routing/forwarding metric)
                                    • walk_ipv6_extensions()  ← ext header chain
                                        • Routing header      ← routing
                                        • Fragment header     ← fragmentation
                                        • Hop-by-Hop, Dest Options, Mobility
                                    └─► decode_icmpv6()  or  print_upper_layer_summary()
```

---

## What each section reports

| Area | IPv4 | IPv6 |
|---|---|---|
| **Addressing** | 32-bit src/dst | 128-bit src/dst |
| **QoS** | TOS → DSCP name + ECN bits | Traffic Class → DSCP name + ECN |
| **Flow** | ID field | 20-bit Flow Label |
| **Routing** | TTL, IPv4 options (RR, LSRR, SSRR, TS) | Hop Limit, Routing extension header |
| **Fragmentation** | DF/MF flags, fragment offset, reassembly note | Fragment ext header: ID, offset, M-flag |
| **ICMP** | Type/code names, echo id/seq, redirect gateway, unreach reason, timestamp | Type/code names, echo, NDP details, MLD, MTU for Too-Big |
| **Other protocols** | TCP/UDP ports, IGMP group, GRE flags, raw hex | Same via extension-header walk |

---

## Build & run

Requires a C++20 compiler (GCC 10+/Clang 12+) and CMake 3.20+.

```bash
# Build (CMake + Ninja)
cmake -S . -B build -G Ninja
cmake --build build

# Or build directly
g++ -std=c++20 -Wall -Wextra -Wpedantic -O2 -o network_layer_reader main.cpp

# Run (CAP_NET_RAW required)
sudo ./build/network_layer_reader eth0   # or: ens3, wlan0, lo …

# Without full root
sudo setcap cap_net_raw+ep ./build/network_layer_reader
./build/network_layer_reader eth0

# List available interfaces
ip link show
```

---

## Implementation notes

- **C++20**, compiled with `-Wall -Wextra -Wpedantic`.
- `std::span<const std::uint8_t>` is used throughout to pass packet buffers —
  bounds are carried with the pointer, eliminating `(ptr, len)` mismatch bugs.
- All wire-format access goes through `std::memcpy`-based helpers
  (`read_be16`, `read_be32`, `read_unaligned<T>`) instead of `reinterpret_cast`
  over raw bytes, which avoids strict-aliasing and unaligned-access UB.
- Lookup tables return `std::string_view` (no per-packet string copies).
- Signal flag is `std::atomic<bool>` with `memory_order_relaxed`; the handler
  has `extern "C"` linkage.
- Receive buffer is a `std::unique_ptr<std::array<std::uint8_t, 65536>>` —
  no raw `new[]` / `delete[]`.
- All internal helpers live in an anonymous namespace.
