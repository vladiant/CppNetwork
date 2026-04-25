#include <sstream>

#include "../packet.hpp"

namespace appsniff {

namespace {

// RTP runs over UDP, typically on dynamically negotiated even-numbered ports.
// We use a heuristic: version=2, payload type in the audio/video range, and
// reserved bits sane. False positives are still possible — RTP has no magic.

const char* payload_type_name(std::uint8_t pt) {
  // Common static payload types from RFC 3551.
  switch (pt) {
    case 0:
      return "PCMU";
    case 3:
      return "GSM";
    case 4:
      return "G723";
    case 8:
      return "PCMA";
    case 9:
      return "G722";
    case 10:
      return "L16-stereo";
    case 11:
      return "L16-mono";
    case 14:
      return "MPA";
    case 18:
      return "G729";
    case 25:
      return "CelB";
    case 26:
      return "JPEG";
    case 28:
      return "nv";
    case 31:
      return "H261";
    case 32:
      return "MPV";
    case 33:
      return "MP2T";
    case 34:
      return "H263";
    default:
      return nullptr;
  }
}

bool plausible_rtp_port(std::uint16_t p) {
  // Heuristic: most RTP traffic uses high (>=1024), even ports.
  // Allow odd as well for RTCP-mux-like deployments. Skip ports we already
  // strongly recognize for other UDP protocols.
  if (p == 53 || p == 5353 || p == 5355) return false;  // DNS/mDNS/LLMNR
  if (p == 443 || p == 80 || p == 8443) return false;   // QUIC
  return p >= 1024;
}

}  // namespace

bool try_parse_rtp(const PacketView& pkt) {
  if (pkt.proto != IpProto::Udp) return false;
  if (!plausible_rtp_port(pkt.src_port) || !plausible_rtp_port(pkt.dst_port))
    return false;
  const auto& d = pkt.payload;
  if (d.size() < 12) return false;

  const std::uint8_t b0 = d[0];
  const std::uint8_t b1 = d[1];
  const std::uint8_t version = (b0 >> 6) & 0x03;
  if (version != 2) return false;

  const std::uint8_t cc = b0 & 0x0F;
  const std::uint8_t marker = (b1 >> 7) & 0x01;
  const std::uint8_t pt = b1 & 0x7F;

  // Reject obvious RTCP packet types (200..208) which share the v=2 prefix
  // but use the marker+PT bits as a packet type byte >= 200.
  if (((b1 & 0x7F) | 0x80) == b1 && b1 >= 200 && b1 <= 211) return false;

  // Need room for the fixed header + CSRC list.
  const std::size_t header_len = 12u + 4u * cc;
  if (d.size() < header_len) return false;

  const std::uint16_t seq = static_cast<std::uint16_t>((d[2] << 8) | d[3]);
  const std::uint32_t ts = (static_cast<std::uint32_t>(d[4]) << 24) |
                           (static_cast<std::uint32_t>(d[5]) << 16) |
                           (static_cast<std::uint32_t>(d[6]) << 8) |
                           static_cast<std::uint32_t>(d[7]);
  const std::uint32_t ssrc = (static_cast<std::uint32_t>(d[8]) << 24) |
                             (static_cast<std::uint32_t>(d[9]) << 16) |
                             (static_cast<std::uint32_t>(d[10]) << 8) |
                             static_cast<std::uint32_t>(d[11]);

  // Stronger filter: require either a known static PT or a dynamic one
  // (96..127) to reduce false positives on random UDP traffic.
  const char* name = payload_type_name(pt);
  const bool dynamic = (pt >= 96 && pt <= 127);
  if (!name && !dynamic) return false;

  std::ostringstream info;
  info << "PT=" << static_cast<unsigned>(pt);
  if (name)
    info << '(' << name << ')';
  else if (dynamic)
    info << "(dynamic)";
  info << " seq=" << seq << " ts=" << ts << " ssrc=0x" << std::hex << ssrc
       << std::dec << " marker=" << static_cast<unsigned>(marker)
       << " cc=" << static_cast<unsigned>(cc);

  log_line("RTP", pkt, info.str());
  return true;
}

}  // namespace appsniff
