#pragma once

#include <netinet/in.h>  // IPPROTO_* constants

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace transport {

using byte_span = std::span<const std::uint8_t>;

// IP protocol numbers we care about by name. Values come from the Linux
// <netinet/in.h> header (IANA "Assigned Internet Protocol Numbers").
enum class IpProto : std::uint8_t {
  ICMP = IPPROTO_ICMP,
  IGMP = IPPROTO_IGMP,
  TCP = IPPROTO_TCP,
  UDP = IPPROTO_UDP,
  IPv6 = IPPROTO_IPV6,
  GRE = IPPROTO_GRE,
  ESP = IPPROTO_ESP,
  AH = IPPROTO_AH,
  ICMPv6 = IPPROTO_ICMPV6,
  SCTP = IPPROTO_SCTP,
  UDPLite = IPPROTO_UDPLITE,
};

// Decode an IPv4 packet starting at the IPv4 header. Returns true if a
// recognised IPv4 packet was printed.
[[nodiscard]] bool decode_ipv4(byte_span packet);

// Decode an IPv6 packet starting at the IPv6 header.
[[nodiscard]] bool decode_ipv6(byte_span packet);

// Human-readable IANA name for an IP protocol number.
[[nodiscard]] std::string_view protocol_name(std::uint8_t proto) noexcept;

}  // namespace transport
