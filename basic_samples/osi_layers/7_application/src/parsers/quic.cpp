#include <iomanip>
#include <sstream>

#include "../packet.hpp"

namespace appsniff {

// QUIC long-header form (RFC 9000):
//  bit 7 = Header Form (1 = long)
//  bit 6 = Fixed Bit (must be 1)
//  bits 5..4 = Long Packet Type
//  Followed by 4-byte Version, then DCID/SCID lengths and IDs.
// Short-header packets (1-RTT) only have a destination connection id and
// are indistinguishable from random bytes — we only flag long-header.

namespace {

const char* long_pkt_type(std::uint8_t v, std::uint32_t version) {
  // QUIC v1: 00 Initial, 01 0-RTT, 10 Handshake, 11 Retry
  if (version == 0x00000001) {
    switch (v & 0x03) {
      case 0:
        return "Initial";
      case 1:
        return "0-RTT";
      case 2:
        return "Handshake";
      case 3:
        return "Retry";
    }
  }
  return "Long";
}

bool plausible_quic_port(std::uint16_t p) {
  return p == 443 || p == 80 || p == 8443;
}

}  // namespace

bool try_parse_quic(const PacketView& pkt) {
  if (pkt.proto != IpProto::Udp) return false;
  if (!plausible_quic_port(pkt.src_port) && !plausible_quic_port(pkt.dst_port))
    return false;

  const auto& d = pkt.payload;
  if (d.size() < 7) return false;

  const std::uint8_t first = d[0];
  const bool long_header = (first & 0x80) != 0;
  const bool fixed_bit = (first & 0x40) != 0;
  if (!long_header || !fixed_bit) return false;

  const std::uint32_t version = (static_cast<std::uint32_t>(d[1]) << 24) |
                                (static_cast<std::uint32_t>(d[2]) << 16) |
                                (static_cast<std::uint32_t>(d[3]) << 8) |
                                static_cast<std::uint32_t>(d[4]);

  // Version Negotiation is signalled by version == 0.
  const bool version_negotiation = (version == 0);

  const std::uint8_t dcid_len = d[5];
  if (static_cast<std::size_t>(6) + dcid_len > d.size()) return false;

  std::ostringstream info;
  info << "v=0x" << std::hex << std::setw(8) << std::setfill('0') << version
       << std::dec;
  if (version_negotiation) {
    info << " VersionNegotiation";
  } else {
    const std::uint8_t pkt_type = (first >> 4) & 0x03;
    info << " type=" << long_pkt_type(pkt_type, version);
  }
  info << " dcid_len=" << static_cast<unsigned>(dcid_len);

  log_line("QUIC", pkt, info.str());
  return true;
}

}  // namespace appsniff
