#include "transport_sniffer.hpp"

#include <arpa/inet.h>
#include <netdb.h>          // getservbyport
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace transport {

namespace {

using std::uint16_t;
using std::uint32_t;
using std::uint8_t;

// ---------- Safe, alignment-agnostic header reads (no reinterpret_cast) ----

template <typename T>
[[nodiscard]] std::optional<T> peek(byte_span s,
                                    std::size_t offset = 0) noexcept {
  if (offset + sizeof(T) > s.size()) return std::nullopt;
  T out{};
  std::memcpy(&out, s.data() + offset, sizeof(T));
  return out;
}

// ---------- Port & protocol name tables -----------------------------------

// Look up the IANA service name for a port/protocol pair via the system
// service database (glibc queries /etc/services and/or NSS). This replaces a
// hand-maintained table with an OS-provided, extensible one.
//
// Note: getservbyport() returns a pointer to static storage and is therefore
// not thread-safe. This sniffer is single-threaded, so that is fine.
[[nodiscard]] std::optional<std::string_view> well_known_port(
    uint16_t port, const char* proto) noexcept {
  const servent* s = ::getservbyport(htons(port), proto);
  if (s == nullptr || s->s_name == nullptr) return std::nullopt;
  return std::string_view{s->s_name};
}

struct ProtoName {
  uint8_t proto;
  std::string_view name;
};

constexpr std::array kProtoNames = std::to_array<ProtoName>({
    {IPPROTO_ICMP, "ICMP"},        {IPPROTO_IGMP, "IGMP"},
    {IPPROTO_TCP, "TCP"},          {IPPROTO_EGP, "EGP"},
    {IPPROTO_PUP, "PUP"},          {IPPROTO_UDP, "UDP"},
    {IPPROTO_IDP, "IDP"},          {IPPROTO_TP, "TP"},
    {IPPROTO_DCCP, "DCCP"},        {IPPROTO_IPV6, "IPv6-in-IPv4"},
    {IPPROTO_RSVP, "RSVP"},        {IPPROTO_GRE, "GRE"},
    {IPPROTO_ESP, "IPsec ESP"},    {IPPROTO_AH, "IPsec AH"},
    {IPPROTO_ICMPV6, "ICMPv6"},    {IPPROTO_MTP, "MTP"},
    {IPPROTO_ENCAP, "ENCAP"},      {IPPROTO_PIM, "PIM"},
    {IPPROTO_COMP, "IPComp"},      {IPPROTO_SCTP, "SCTP"},
    {IPPROTO_UDPLITE, "UDP-Lite"}, {IPPROTO_MPLS, "MPLS-in-IP"},
    {IPPROTO_RAW, "RAW"},
});

// ---------- TCP flag decoding ---------------------------------------------

struct TcpFlag {
  uint8_t mask;
  std::string_view name;
};

// Six classic flags come from <netinet/tcp.h> (TH_*). ECE/CWR (RFC 3168 ECN)
// have no portable POSIX macro — <linux/tcp.h> only exposes big-endian
// TCP_FLAG_* constants meant for the 32-bit word — so they are literal here.
constexpr std::array kTcpFlags = std::to_array<TcpFlag>({
    {TH_FIN, "FIN"},
    {TH_SYN, "SYN"},
    {TH_RST, "RST"},
    {TH_PUSH, "PSH"},
    {TH_ACK, "ACK"},
    {TH_URG, "URG"},
    {0x40, "ECE"},  // RFC 3168
    {0x80, "CWR"},  // RFC 3168
});

[[nodiscard]] std::string tcp_flags_to_string(uint8_t flags) {
  std::string out;
  for (const auto& f : kTcpFlags) {
    if ((flags & f.mask) == 0) continue;
    if (!out.empty()) out.push_back(',');
    out.append(f.name);
  }
  return out.empty() ? std::string{"<none>"} : out;
}

// ---------- Pretty port printing ------------------------------------------

void print_port(std::ostream& os, std::string_view label, uint16_t port,
                const char* proto) {
  os << "        " << label << " : " << port;
  if (auto name = well_known_port(port, proto)) os << " (" << *name << ')';
  os << '\n';
}

// ---------- Transport decoders --------------------------------------------

void print_tcp(byte_span payload) {
  auto th = peek<tcphdr>(payload);
  if (!th) {
    std::cout << "  [TCP] truncated header (" << payload.size() << " bytes)\n";
    return;
  }
  const uint16_t sport = ntohs(th->th_sport);
  const uint16_t dport = ntohs(th->th_dport);
  const uint32_t seq = ntohl(th->th_seq);
  const uint32_t ack = ntohl(th->th_ack);
  const auto hdrlen = static_cast<std::size_t>(th->th_off) * 4U;
  const uint16_t win = ntohs(th->th_win);

  std::cout << "  [TCP] Transmission Control Protocol (connection-oriented, "
               "reliable)\n";
  print_port(std::cout, "Src port", sport, "tcp");
  print_port(std::cout, "Dst port", dport, "tcp");
  std::cout << "        Seq      : " << seq << '\n'
            << "        Ack      : " << ack << '\n'
            << "        Hdr len  : " << hdrlen << " bytes\n"
            << "        Flags    : " << tcp_flags_to_string(th->th_flags)
            << '\n'
            << "        Flow ctl : sliding-window, advertised window = " << win
            << " bytes\n"
            << "        Checksum : 0x" << std::hex << ntohs(th->th_sum)
            << std::dec << '\n';
}

void print_quic_hint(byte_span udp_payload, uint16_t sport, uint16_t dport) {
  if (udp_payload.empty()) return;
  if (sport != 443 && dport != 443) return;

  const uint8_t first = udp_payload[0];
  const bool long_hdr = (first & 0x80U) != 0;
  const bool fixed = (first & 0x40U) != 0;
  if (!fixed) return;

  std::cout << "  [QUIC] Likely QUIC (RFC 9000) over UDP\n"
            << "         First byte    : 0x" << std::hex
            << static_cast<int>(first) << std::dec
            << "\n         Header form   : " << (long_hdr ? "long" : "short")
            << "\n         Flow control  : stream- & connection-level "
               "(MAX_DATA / MAX_STREAM_DATA frames)"
            << "\n         Reliability   : reliable, multiplexed streams, "
               "built-in TLS 1.3\n";

  if (long_hdr) {
    if (auto ver = peek<uint32_t>(udp_payload, 1)) {
      const uint32_t v = ntohl(*ver);
      std::cout << "         Version       : 0x" << std::hex << v << std::dec
                << (v == 0x00000001U ? " (QUIC v1)" : "") << '\n';
    }
  }
}

void print_udp(byte_span payload) {
  auto uh = peek<udphdr>(payload);
  if (!uh) {
    std::cout << "  [UDP] truncated header (" << payload.size() << " bytes)\n";
    return;
  }
  const uint16_t sport = ntohs(uh->uh_sport);
  const uint16_t dport = ntohs(uh->uh_dport);
  const uint16_t ulen = ntohs(uh->uh_ulen);

  std::cout << "  [UDP] User Datagram Protocol (connectionless, unreliable)\n";
  print_port(std::cout, "Src port", sport, "udp");
  print_port(std::cout, "Dst port", dport, "udp");
  std::cout << "        Length   : " << ulen << " bytes\n"
            << "        Checksum : 0x" << std::hex << ntohs(uh->uh_sum)
            << std::dec << '\n'
            << "        Flow ctl : none at UDP layer (application-defined)\n";

  if (payload.size() > sizeof(udphdr)) {
    print_quic_hint(payload.subspan(sizeof(udphdr)), sport, dport);
  }
}

// SCTP common header (RFC 9260).
struct SctpCommonHdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t verification_tag;
  uint32_t checksum;
} __attribute__((packed));

[[nodiscard]] constexpr std::string_view sctp_chunk_name(uint8_t t) noexcept {
  switch (t) {
    case 0:
      return "DATA";
    case 1:
      return "INIT";
    case 2:
      return "INIT ACK";
    case 3:
      return "SACK";
    case 4:
      return "HEARTBEAT";
    case 5:
      return "HEARTBEAT ACK";
    case 6:
      return "ABORT";
    case 7:
      return "SHUTDOWN";
    case 8:
      return "SHUTDOWN ACK";
    case 9:
      return "ERROR";
    case 10:
      return "COOKIE ECHO";
    case 11:
      return "COOKIE ACK";
    case 14:
      return "SHUTDOWN COMPLETE";
    default:
      return "?";
  }
}

void print_sctp(byte_span payload) {
  auto sh = peek<SctpCommonHdr>(payload);
  if (!sh) {
    std::cout << "  [SCTP] truncated header (" << payload.size() << " bytes)\n";
    return;
  }
  std::cout << "  [SCTP] Stream Control Transmission Protocol (reliable, "
               "message-oriented, multi-streamed, multi-homed)\n"
            << "         Src port     : " << ntohs(sh->src_port) << '\n'
            << "         Dst port     : " << ntohs(sh->dst_port) << '\n'
            << "         Verif. tag   : 0x" << std::hex
            << ntohl(sh->verification_tag) << std::dec << '\n'
            << "         Checksum     : 0x" << std::hex << ntohl(sh->checksum)
            << std::dec << " (CRC32c)\n"
            << "         Flow control : per-association rwnd + per-stream "
               "sequencing (SACK-based)\n";

  std::size_t off = sizeof(SctpCommonHdr);
  for (int n = 0; n < 8 && off + 4 <= payload.size(); ++n) {
    const uint8_t type = payload[off];
    const uint16_t clen = static_cast<uint16_t>(
        (static_cast<uint16_t>(payload[off + 2]) << 8) | payload[off + 3]);
    if (clen < 4 || off + clen > payload.size()) break;

    std::cout << "         Chunk#" << n
              << "     : type=" << static_cast<int>(type) << " ("
              << sctp_chunk_name(type) << "), length=" << clen << '\n';

    off += (static_cast<std::size_t>(clen) + 3U) & ~std::size_t{3};
  }
}

void print_other(uint8_t proto, std::size_t payload_len) {
  std::cout
      << "  [L4] Protocol " << static_cast<int>(proto) << " ("
      << protocol_name(proto) << ")\n"
      << "       Payload length : " << payload_len << " bytes\n"
      << "       (Basic info only — no deep decoder for this protocol.)\n";
}

// ---------- Address formatting --------------------------------------------

[[nodiscard]] std::string ipv4_to_str(in_addr a) {
  std::array<char, INET_ADDRSTRLEN> buf{};
  ::inet_ntop(AF_INET, &a, buf.data(), buf.size());
  return std::string{buf.data()};
}

[[nodiscard]] std::string ipv6_to_str(const in6_addr& a) {
  std::array<char, INET6_ADDRSTRLEN> buf{};
  ::inet_ntop(AF_INET6, &a, buf.data(), buf.size());
  return std::string{buf.data()};
}

void dispatch_l4(uint8_t proto, byte_span payload) {
  switch (proto) {
    case IPPROTO_TCP:
      print_tcp(payload);
      break;
    case IPPROTO_UDP:
      print_udp(payload);
      break;
    case IPPROTO_SCTP:
      print_sctp(payload);
      break;
    default:
      print_other(proto, payload.size());
      break;
  }
}

}  // namespace

// ---------- Public API -----------------------------------------------------

std::string_view protocol_name(uint8_t proto) noexcept {
  const auto it =
      std::find_if(kProtoNames.begin(), kProtoNames.end(),
                   [proto](const ProtoName& p) { return p.proto == proto; });
  return (it == kProtoNames.end()) ? std::string_view{"Unknown"} : it->name;
}

bool decode_ipv4(byte_span packet) {
  auto ip = peek<iphdr>(packet);
  if (!ip || ip->version != 4) return false;

  const auto ihl = static_cast<std::size_t>(ip->ihl) * 4U;
  if (ihl < sizeof(iphdr) || ihl > packet.size()) return false;

  const uint16_t total = ntohs(ip->tot_len);
  const std::size_t payload_len = (total > ihl && total <= packet.size())
                                      ? (total - ihl)
                                      : (packet.size() - ihl);

  in_addr src{}, dst{};
  src.s_addr = ip->saddr;
  dst.s_addr = ip->daddr;

  std::cout << "IPv4 " << ipv4_to_str(src) << " -> " << ipv4_to_str(dst)
            << " | proto=" << static_cast<int>(ip->protocol) << " ("
            << protocol_name(ip->protocol) << ')' << " | total=" << total
            << "B\n";

  dispatch_l4(ip->protocol, packet.subspan(ihl, payload_len));
  std::cout << "----\n";
  return true;
}

bool decode_ipv6(byte_span packet) {
  auto ip = peek<ip6_hdr>(packet);
  if (!ip) return false;
  if (((ntohl(ip->ip6_flow) >> 28) & 0xFU) != 6U) return false;

  const std::size_t payload_len = ntohs(ip->ip6_plen);
  const uint8_t next = ip->ip6_nxt;

  std::cout << "IPv6 " << ipv6_to_str(ip->ip6_src) << " -> "
            << ipv6_to_str(ip->ip6_dst) << " | next=" << static_cast<int>(next)
            << " (" << protocol_name(next) << ')'
            << " | payload=" << payload_len << "B\n";

  const std::size_t available = packet.size() - sizeof(ip6_hdr);
  const std::size_t l4_len =
      (payload_len != 0 && payload_len <= available) ? payload_len : available;

  dispatch_l4(next, packet.subspan(sizeof(ip6_hdr), l4_len));
  std::cout << "----\n";
  return true;
}

}  // namespace transport
