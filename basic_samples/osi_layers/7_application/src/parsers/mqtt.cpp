#include <sstream>
#include <string>
#include <string_view>

#include "../packet.hpp"

namespace appsniff {

namespace {

bool is_mqtt_port(std::uint16_t p) { return p == 1883 || p == 8883; }

const char* packet_type_name(std::uint8_t t) {
  switch (t) {
    case 1:
      return "CONNECT";
    case 2:
      return "CONNACK";
    case 3:
      return "PUBLISH";
    case 4:
      return "PUBACK";
    case 5:
      return "PUBREC";
    case 6:
      return "PUBREL";
    case 7:
      return "PUBCOMP";
    case 8:
      return "SUBSCRIBE";
    case 9:
      return "SUBACK";
    case 10:
      return "UNSUBSCRIBE";
    case 11:
      return "UNSUBACK";
    case 12:
      return "PINGREQ";
    case 13:
      return "PINGRESP";
    case 14:
      return "DISCONNECT";
    case 15:
      return "AUTH";
    default:
      return "MQTT?";
  }
}

// Decode MQTT variable-byte integer. Returns true on success.
bool decode_varint(const std::uint8_t* d, std::size_t avail,
                   std::size_t& consumed, std::uint32_t& out) {
  out = 0;
  std::uint32_t mult = 1;
  consumed = 0;
  for (int i = 0; i < 4; ++i) {
    if (i >= static_cast<int>(avail)) return false;
    const std::uint8_t b = d[i];
    out += (b & 0x7Fu) * mult;
    consumed = static_cast<std::size_t>(i + 1);
    if ((b & 0x80) == 0) return true;
    mult *= 128;
    if (mult > 128u * 128u * 128u * 128u) return false;
  }
  return false;
}

}  // namespace

bool try_parse_mqtt(const PacketView& pkt) {
  if (pkt.proto != IpProto::Tcp) return false;
  if (!is_mqtt_port(pkt.src_port) && !is_mqtt_port(pkt.dst_port)) return false;

  const auto& d = pkt.payload;
  if (d.size() < 2) return false;

  const std::uint8_t fixed = d[0];
  const std::uint8_t ptype = (fixed >> 4) & 0x0F;
  const std::uint8_t flags = fixed & 0x0F;
  if (ptype == 0 || ptype > 15) return false;

  std::size_t vlen = 0;
  std::uint32_t remaining = 0;
  if (!decode_varint(d.data() + 1, d.size() - 1, vlen, remaining)) return false;

  std::ostringstream info;
  info << packet_type_name(ptype) << " flags=0x" << std::hex
       << static_cast<unsigned>(flags) << std::dec
       << " remaining=" << remaining;

  const std::size_t body_off = 1 + vlen;

  if (ptype == 1 /* CONNECT */ && d.size() >= body_off + 4) {
    // CONNECT variable header begins with protocol name (UTF-8 string).
    const std::uint16_t name_len =
        static_cast<std::uint16_t>((d[body_off] << 8) | d[body_off + 1]);
    if (body_off + 2 + name_len <= d.size() && name_len <= 16) {
      std::string name(reinterpret_cast<const char*>(d.data() + body_off + 2),
                       name_len);
      info << " proto=\"" << name << '"';
      if (body_off + 2 + name_len < d.size()) {
        info << " level=" << static_cast<unsigned>(d[body_off + 2 + name_len]);
      }
    }
  } else if (ptype == 3 /* PUBLISH */ && d.size() >= body_off + 2) {
    const std::uint16_t tlen =
        static_cast<std::uint16_t>((d[body_off] << 8) | d[body_off + 1]);
    if (body_off + 2 + tlen <= d.size() && tlen < 256) {
      std::string topic(reinterpret_cast<const char*>(d.data() + body_off + 2),
                        tlen);
      const unsigned qos = (flags >> 1) & 0x03;
      info << " qos=" << qos << " topic=\"" << topic << '"';
    }
  }

  log_line("MQTT", pkt, info.str());
  return true;
}

}  // namespace appsniff
