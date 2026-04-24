# datalink_reader

C++ code sample that captures and parses OSI **Layer 2 (Data Link Layer)** frames on Linux using raw sockets

---

## How it works

| Layer | What the code does |
|---|---|
| **Socket creation** | `AF_PACKET` + `SOCK_RAW` + `ETH_P_ALL` — bypasses the network stack and receives every Ethernet frame on the wire |
| **Interface binding** | Uses `ioctl(SIOCGIFINDEX)` + `bind(sockaddr_ll)` to pin to a specific NIC |
| **Frame parsing** | Decodes the Ethernet II header: destination MAC, source MAC, EtherType; also handles **802.1Q VLAN tags** |
| **Payload dump** | Prints the first 64 bytes of the frame payload as hex |

---

## Build & run

```bash
# Compile
cd build
cmake ..
make

# Run (root or CAP_NET_RAW required for raw sockets)
sudo ./datalink_reader eth0      # replace eth0 with your interface, e.g. ens3, wlan0

# Or grant the capability without full root:
sudo setcap cap_net_raw+ep ./datalink_reader
./datalink_reader eth0
```

> **Find your interface name:** run `ip link show` or `ls /sys/class/net/`

---

## Sample output

```
OSI Layer 2 – Data Link Frame Reader
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