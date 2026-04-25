# OSI Layer 1 — Physical

A small Linux/C++17 CMake project that reads what user space can observe of
the **OSI physical layer**:

- physical-link properties of every NIC (MAC, MTU, link UP/DOWN, line rate,
  duplex) via `ethtool` / `SIOC*` ioctls;
- the raw octet/bit stream as it enters or leaves a chosen NIC, captured via
  an `AF_PACKET` / `SOCK_RAW` socket bound with `ETH_P_ALL`. The bytes are
  printed in **hex** and as a **bit string** — the closest representation
  of "bits on the wire" you can get from portable user space (the PHY/MAC
  preamble, SFD and FCS are stripped by the hardware before the kernel
  hands the frame up).

## Build

```bash
cmake -S . -B build
cmake --build build -j
```

## Run

```bash
# 1. List interfaces and their physical properties (no privileges needed):
./build/osi_physical

# 2. Capture raw frames from a NIC (needs CAP_NET_RAW):
sudo ./build/osi_physical eth0 3
# or, instead of sudo:
sudo setcap cap_net_raw=eip ./build/osi_physical
./build/osi_physical eth0 3
```

## Example output

```
Physical-layer properties of eth0:
  eth0              MAC=aa:bb:cc:dd:ee:ff  MTU=1500  link=UP  speed=1000Mb/s  duplex=full

--- frame #1 (RX, 98 bytes on the wire) ---
hex:
ff ff ff ff ff ff aa bb cc dd ee ff 08 06 00 01
...
bits (MSB first per octet):
11111111 11111111 11111111 11111111 11111111 11111111 10101010 ...
```

## Notes / caveats

- True L1 (electrical/optical signalling, line coding such as 4B/5B or
  64b/66b, the preamble and SFD, the FCS) is handled by the PHY chip and
  is **not** visible to user space. This program shows the closest
  approximation Linux exposes.
- On `lo`, `tun*`, virtual or Wi‑Fi (managed mode) interfaces, `ETHTOOL_GSET`
  may fail and speed/duplex won't be printed — that's expected.
- Targets Linux only.
