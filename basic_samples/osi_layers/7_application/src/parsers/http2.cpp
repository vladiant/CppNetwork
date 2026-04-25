#include <cstring>
#include <sstream>
#include <string_view>

#include "../packet.hpp"

namespace appsniff {

namespace {

constexpr std::string_view kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const char* frame_type_name(std::uint8_t t) {
  switch (t) {
    case 0x0:
      return "DATA";
    case 0x1:
      return "HEADERS";
    case 0x2:
      return "PRIORITY";
    case 0x3:
      return "RST_STREAM";
    case 0x4:
      return "SETTINGS";
    case 0x5:
      return "PUSH_PROMISE";
    case 0x6:
      return "PING";
    case 0x7:
      return "GOAWAY";
    case 0x8:
      return "WINDOW_UPDATE";
    case 0x9:
      return "CONTINUATION";
    default:
      return "UNKNOWN";
  }
}

bool plausible_h2_port(std::uint16_t p) {
  // h2c (cleartext) typical ports; TLS-wrapped HTTP/2 is opaque to us.
  return p == 80 || p == 8080 || p == 443 || p == 8443;
}

}  // namespace

bool try_parse_http2(const PacketView& pkt) {
  if (pkt.proto != IpProto::Tcp) return false;
  if (!plausible_h2_port(pkt.src_port) && !plausible_h2_port(pkt.dst_port))
    return false;
  const auto& d = pkt.payload;
  if (d.size() < 9) return false;

  std::size_t off = 0;
  bool saw_preface = false;
  if (d.size() >= kPreface.size() &&
      std::memcmp(d.data(), kPreface.data(), kPreface.size()) == 0) {
    saw_preface = true;
    off = kPreface.size();
  }

  if (off + 9 > d.size() && !saw_preface) return false;

  if (off + 9 <= d.size()) {
    const std::uint32_t length = (static_cast<std::uint32_t>(d[off]) << 16) |
                                 (static_cast<std::uint32_t>(d[off + 1]) << 8) |
                                 static_cast<std::uint32_t>(d[off + 2]);
    const std::uint8_t type = d[off + 3];
    const std::uint8_t flags = d[off + 4];
    const std::uint32_t stream =
        ((static_cast<std::uint32_t>(d[off + 5]) & 0x7F) << 24) |
        (static_cast<std::uint32_t>(d[off + 6]) << 16) |
        (static_cast<std::uint32_t>(d[off + 7]) << 8) |
        static_cast<std::uint32_t>(d[off + 8]);

    // Sanity: length must fit within an HTTP/2 max frame size and
    // type should be a known one (or close).
    if (!saw_preface) {
      if (length > 0x100000) return false;
      if (type > 0x09) return false;
      // Without preface context we want a strong signal: cleartext h2c
      // typically begins a stream with HEADERS or SETTINGS.
      if (type != 0x01 && type != 0x04) return false;
    }

    std::ostringstream info;
    if (saw_preface) info << "client preface; ";
    info << "frame type=" << frame_type_name(type) << " len=" << length
         << " flags=0x" << std::hex << static_cast<unsigned>(flags) << std::dec
         << " stream=" << stream;
    log_line("HTTP/2", pkt, info.str());
    return true;
  }

  if (saw_preface) {
    log_line("HTTP/2", pkt, "client preface");
    return true;
  }
  return false;
}

}  // namespace appsniff
