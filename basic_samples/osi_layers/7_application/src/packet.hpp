#pragma once

#include <netinet/in.h>  // IPPROTO_TCP, IPPROTO_UDP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace appsniff {

enum class IpProto : std::uint8_t {
  Tcp = IPPROTO_TCP,
  Udp = IPPROTO_UDP,
  Other = 0xFF,
};

struct PacketView {
  // L3
  std::string src_ip;
  std::string dst_ip;
  // L4
  IpProto proto = IpProto::Other;
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  // L7 payload
  std::span<const std::uint8_t> payload;
  // Wall-clock timestamp string
  std::string timestamp;
};

// Returns true if a parser took ownership of (recognized) the packet.
// Implementations live in src/parsers/*.cpp
bool try_parse_http(const PacketView&);
bool try_parse_http2(const PacketView&);
bool try_parse_quic(const PacketView&);
bool try_parse_dns(const PacketView&);
bool try_parse_tls(const PacketView&);
bool try_parse_smtp(const PacketView&);
bool try_parse_mqtt(const PacketView&);
bool try_parse_rtp(const PacketView&);

// Helpers shared by parsers.
std::string hex_dump_short(std::span<const std::uint8_t> data,
                           std::size_t max_bytes = 16);
std::string printable_preview(std::span<const std::uint8_t> data,
                              std::size_t max_bytes = 80);

void log_line(std::string_view proto, const PacketView& pkt,
              std::string_view info);

}  // namespace appsniff
