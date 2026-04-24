#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

// ─── Constants ───────────────────────────────────────────────────────────────

constexpr std::size_t kBufferSize = 65536;
constexpr std::size_t kMacAddrLen = 6;

// IP protocol numbers and IPv6 extension header types come from
// <netinet/in.h> as IPPROTO_* macros. OSPF has no standard macro
// in glibc, so we define it locally.
constexpr std::uint8_t kProtoOSPF = 89;

// ─── Globals ─────────────────────────────────────────────────────────────────

std::atomic<bool> g_running{true};
std::uint64_t g_frame_count = 0;

// ─── Signal handler ──────────────────────────────────────────────────────────

extern "C" void signal_handler(int /*sig*/) {
  g_running.store(false, std::memory_order_relaxed);
}

// ─── Byte-buffer helpers (strict-aliasing-safe) ──────────────────────────────

template <typename T>
[[nodiscard]] T read_unaligned(const std::uint8_t* p) noexcept {
  T v;
  std::memcpy(&v, p, sizeof(T));
  return v;
}

[[nodiscard]] std::uint16_t read_be16(const std::uint8_t* p) noexcept {
  return ntohs(read_unaligned<std::uint16_t>(p));
}

[[nodiscard]] std::uint32_t read_be32(const std::uint8_t* p) noexcept {
  return ntohl(read_unaligned<std::uint32_t>(p));
}

// ─── Formatting helpers ──────────────────────────────────────────────────────

[[nodiscard]] std::string mac_to_str(
    std::span<const std::uint8_t, kMacAddrLen> mac) {
  std::ostringstream o;
  for (std::size_t i = 0; i < mac.size(); ++i) {
    if (i) o << ':';
    o << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
      << static_cast<int>(mac[i]);
  }
  return o.str();
}

[[nodiscard]] std::string ipv4_to_str(std::uint32_t addr_net) {
  std::array<char, INET_ADDRSTRLEN> buf{};
  inet_ntop(AF_INET, &addr_net, buf.data(), buf.size());
  return std::string{buf.data()};
}

[[nodiscard]] std::string ipv6_to_str(const void* addr) {
  std::array<char, INET6_ADDRSTRLEN> buf{};
  inet_ntop(AF_INET6, addr, buf.data(), buf.size());
  return std::string{buf.data()};
}

[[nodiscard]] std::string hex_byte(std::uint8_t b) {
  std::ostringstream o;
  o << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
    << static_cast<int>(b);
  return o.str();
}

[[nodiscard]] std::string hex_word(std::uint16_t w) {
  std::ostringstream o;
  o << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
    << w;
  return o.str();
}

void hex_dump(std::span<const std::uint8_t> data, std::size_t max_bytes = 32,
              std::string_view prefix = "    ") {
  const std::size_t limit = std::min(data.size(), max_bytes);
  for (std::size_t i = 0; i < limit; i += 16) {
    std::cout << prefix << std::hex << std::setw(4) << std::setfill('0') << i
              << "  ";
    for (std::size_t j = i; j < std::min(i + 16, limit); ++j)
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(data[j]) << ' ';
    std::cout << '\n';
  }
  std::cout << std::dec;
  if (data.size() > max_bytes)
    std::cout << prefix << "... (" << (data.size() - max_bytes)
              << " more bytes)\n";
}

// ─── Protocol name tables ────────────────────────────────────────────────────

[[nodiscard]] std::string ip_proto_name(std::uint8_t proto) {
  switch (proto) {
    case IPPROTO_ICMP:
      return "ICMP";
    case IPPROTO_IGMP:
      return "IGMP";
    case IPPROTO_TCP:
      return "TCP";
    case IPPROTO_UDP:
      return "UDP";
    case IPPROTO_GRE:
      return "GRE";
    case IPPROTO_ESP:
      return "IPSec ESP";
    case IPPROTO_AH:
      return "IPSec AH";
    case IPPROTO_ICMPV6:
      return "ICMPv6";
    case kProtoOSPF:
      return "OSPF";
    case IPPROTO_SCTP:
      return "SCTP";
    default:
      return "Unknown (" + std::to_string(proto) + ")";
  }
}

[[nodiscard]] std::string icmp4_type_name(std::uint8_t type) {
  switch (type) {
    case ICMP_ECHOREPLY:
      return "Echo Reply";
    case ICMP_DEST_UNREACH:
      return "Destination Unreachable";
    case ICMP_SOURCE_QUENCH:
      return "Source Quench";
    case ICMP_REDIRECT:
      return "Redirect";
    case ICMP_ECHO:
      return "Echo Request";
    case ICMP_TIME_EXCEEDED:
      return "Time Exceeded";
    case ICMP_PARAMETERPROB:
      return "Parameter Problem";
    case ICMP_TIMESTAMP:
      return "Timestamp";
    case ICMP_TIMESTAMPREPLY:
      return "Timestamp Reply";
    case ICMP_ADDRESS:
      return "Address Mask Request";
    case ICMP_ADDRESSREPLY:
      return "Address Mask Reply";
    default:
      return "Unknown (" + std::to_string(type) + ")";
  }
}

[[nodiscard]] std::string icmp4_unreach_name(std::uint8_t code) {
  switch (code) {
    case ICMP_NET_UNREACH:
      return "Net Unreachable";
    case ICMP_HOST_UNREACH:
      return "Host Unreachable";
    case ICMP_PROT_UNREACH:
      return "Protocol Unreachable";
    case ICMP_PORT_UNREACH:
      return "Port Unreachable";
    case ICMP_FRAG_NEEDED:
      return "Fragmentation Needed (DF set)";
    case ICMP_SR_FAILED:
      return "Source Route Failed";
    case ICMP_NET_UNKNOWN:
      return "Destination Network Unknown";
    case ICMP_HOST_UNKNOWN:
      return "Destination Host Unknown";
    default:
      return "Unknown Code (" + std::to_string(code) + ")";
  }
}

[[nodiscard]] std::string icmp4_redirect_name(std::uint8_t code) {
  switch (code) {
    case ICMP_REDIR_NET:
      return "Redirect for Network";
    case ICMP_REDIR_HOST:
      return "Redirect for Host";
    case ICMP_REDIR_NETTOS:
      return "Redirect for TOS & Network";
    case ICMP_REDIR_HOSTTOS:
      return "Redirect for TOS & Host";
    default:
      return "Unknown Code (" + std::to_string(code) + ")";
  }
}

[[nodiscard]] std::string icmp6_type_name(std::uint8_t type) {
  switch (type) {
    case ICMP6_DST_UNREACH:
      return "Destination Unreachable";
    case ICMP6_PACKET_TOO_BIG:
      return "Packet Too Big";
    case ICMP6_TIME_EXCEEDED:
      return "Time Exceeded";
    case ICMP6_PARAM_PROB:
      return "Parameter Problem";
    case ICMP6_ECHO_REQUEST:
      return "Echo Request";
    case ICMP6_ECHO_REPLY:
      return "Echo Reply";
    case ND_ROUTER_SOLICIT:
      return "Router Solicitation (NDP)";
    case ND_ROUTER_ADVERT:
      return "Router Advertisement (NDP)";
    case ND_NEIGHBOR_SOLICIT:
      return "Neighbor Solicitation (NDP)";
    case ND_NEIGHBOR_ADVERT:
      return "Neighbor Advertisement (NDP)";
    case ND_REDIRECT:
      return "Redirect (NDP)";
    case MLD_LISTENER_QUERY:
      return "MLD Listener Query";
    case MLD_LISTENER_REPORT:
      return "MLD Listener Report";
    case MLD_LISTENER_REDUCTION:
      return "MLD Listener Done";
    default:
      return "Unknown (" + std::to_string(type) + ")";
  }
}

[[nodiscard]] std::string ipv6_ext_name(std::uint8_t type) {
  // Note: IPPROTO_HOPOPTS (0) and IPPROTO_ESP (50) / IPPROTO_AH (51)
  // overlap with the ip_proto_name() table — this is intentional:
  // in an IPv6 next-header chain these values denote extension headers.
  switch (type) {
    case IPPROTO_HOPOPTS:
      return "Hop-by-Hop Options";
    case IPPROTO_ROUTING:
      return "Routing";
    case IPPROTO_FRAGMENT:
      return "Fragment";
    case IPPROTO_ESP:
      return "ESP";
    case IPPROTO_AH:
      return "Authentication";
    case IPPROTO_DSTOPTS:
      return "Destination Options";
    case IPPROTO_MH:
      return "Mobility";
    case IPPROTO_NONE:
      return "No Next Header";
    default:
      return "Unknown Extension (" + std::to_string(type) + ")";
  }
}

[[nodiscard]] std::string dscp_name(std::uint8_t dscp) {
  // DSCP constants come from <netinet/ip.h> as IPTOS_CLASS_CSx /
  // IPTOS_DSCP_{AFxy,EF,LE,VA}. Those macros encode the full TOS byte
  // (DSCP << 2), so we right-shift by 2 to compare against the 6-bit
  // DSCP field.
  switch (dscp) {
    case IPTOS_CLASS_CS0 >> 2:
      return "Default (BE)";
    case IPTOS_CLASS_CS1 >> 2:
      return "CS1";
    case IPTOS_CLASS_CS2 >> 2:
      return "CS2";
    case IPTOS_CLASS_CS3 >> 2:
      return "CS3";
    case IPTOS_CLASS_CS4 >> 2:
      return "CS4";
    case IPTOS_CLASS_CS5 >> 2:
      return "CS5";
    case IPTOS_CLASS_CS6 >> 2:
      return "CS6";
    case IPTOS_CLASS_CS7 >> 2:
      return "CS7";
    case IPTOS_DSCP_AF11 >> 2:
      return "AF11";
    case IPTOS_DSCP_AF12 >> 2:
      return "AF12";
    case IPTOS_DSCP_AF13 >> 2:
      return "AF13";
    case IPTOS_DSCP_AF21 >> 2:
      return "AF21";
    case IPTOS_DSCP_AF22 >> 2:
      return "AF22";
    case IPTOS_DSCP_AF23 >> 2:
      return "AF23";
    case IPTOS_DSCP_AF31 >> 2:
      return "AF31";
    case IPTOS_DSCP_AF32 >> 2:
      return "AF32";
    case IPTOS_DSCP_AF33 >> 2:
      return "AF33";
    case IPTOS_DSCP_AF41 >> 2:
      return "AF41";
    case IPTOS_DSCP_AF42 >> 2:
      return "AF42";
    case IPTOS_DSCP_AF43 >> 2:
      return "AF43";
    case IPTOS_DSCP_EF >> 2:
      return "EF (Expedited Forwarding)";
    case IPTOS_DSCP_VA >> 2:
      return "VA (Voice-Admit)";
    case IPTOS_DSCP_LE >> 2:
      return "LE (Lower-Effort)";
    default:
      return "Custom (" + std::to_string(dscp) + ")";
  }
}

// ─── IPv4 option decoder ─────────────────────────────────────────────────────

void decode_ipv4_options(std::span<const std::uint8_t> opts) {
  std::size_t i = 0;
  while (i < opts.size()) {
    const std::uint8_t kind = opts[i];
    if (kind == 0) {
      std::cout << "      [EOOL - End of Option List]\n";
      break;
    }
    if (kind == 1) {
      std::cout << "      [NOP - No Operation]\n";
      ++i;
      continue;
    }
    if (i + 1 >= opts.size()) break;
    const std::uint8_t opt_len = opts[i + 1];
    if (opt_len < 2 || i + opt_len > opts.size()) break;

    switch (kind) {
      case 7:
        std::cout << "      [Record Route  len=" << static_cast<int>(opt_len)
                  << "]\n";
        break;
      case 68:
        std::cout << "      [Timestamp     len=" << static_cast<int>(opt_len)
                  << "]\n";
        break;
      case 131:
        std::cout << "      [Loose  Source Route len="
                  << static_cast<int>(opt_len) << "]\n";
        break;
      case 137:
        std::cout << "      [Strict Source Route len="
                  << static_cast<int>(opt_len) << "]\n";
        break;
      case 130:
        std::cout << "      [Security      len=" << static_cast<int>(opt_len)
                  << "]\n";
        break;
      default:
        std::cout << "      [Option kind=" << static_cast<int>(kind)
                  << " len=" << static_cast<int>(opt_len) << "]\n";
        break;
    }
    i += opt_len;
  }
}

// ─── ICMP v4 decoder ─────────────────────────────────────────────────────────

void decode_icmpv4(std::span<const std::uint8_t> data) {
  if (data.size() < 8) {
    std::cout << "  [ICMPv4 too short]\n";
    return;
  }
  icmphdr hdr{};
  std::memcpy(&hdr, data.data(), sizeof(hdr));
  const std::uint8_t type = hdr.type;
  const std::uint8_t code = hdr.code;
  const std::uint16_t csum = ntohs(hdr.checksum);

  std::cout << "  ╔═ ICMPv4 ══════════════════════════════════════════╗\n";
  std::cout << "  ║  Type     : " << static_cast<int>(type) << "  ("
            << icmp4_type_name(type) << ")\n";
  std::cout << "  ║  Code     : " << static_cast<int>(code) << "\n";
  std::cout << "  ║  Checksum : " << hex_word(csum) << "\n";

  switch (type) {
    case ICMP_ECHO:
    case ICMP_ECHOREPLY:
      std::cout << "  ║  ID       : " << ntohs(hdr.un.echo.id) << "\n";
      std::cout << "  ║  Sequence : " << ntohs(hdr.un.echo.sequence) << "\n";
      if (data.size() > 8)
        std::cout << "  ║  Data len : " << (data.size() - 8) << " bytes\n";
      break;

    case ICMP_DEST_UNREACH:
      std::cout << "  ║  Reason   : " << icmp4_unreach_name(code) << "\n";
      if (code == ICMP_FRAG_NEEDED)
        std::cout << "  ║  Next-Hop MTU : " << ntohs(hdr.un.frag.mtu) << "\n";
      if (data.size() >= 8 + 20)
        std::cout << "  ║  [Embedded original IP header present]\n";
      break;

    case ICMP_REDIRECT:
      std::cout << "  ║  Reason   : " << icmp4_redirect_name(code) << "\n";
      std::cout << "  ║  Gateway  : " << ipv4_to_str(hdr.un.gateway) << "\n";
      break;

    case ICMP_TIME_EXCEEDED:
      std::cout << "  ║  Reason   : "
                << (code == ICMP_EXC_TTL        ? "TTL Exceeded in Transit"
                    : code == ICMP_EXC_FRAGTIME ? "Fragment Reassembly Timeout"
                                                : "Unknown")
                << " (" << static_cast<int>(code) << ")\n";
      break;

    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
      std::cout << "  ║  ID       : " << ntohs(hdr.un.echo.id) << "\n";
      std::cout << "  ║  Sequence : " << ntohs(hdr.un.echo.sequence) << "\n";
      if (data.size() >= 20) {
        const std::uint32_t orig = read_be32(data.data() + 8);
        const std::uint32_t rx = read_be32(data.data() + 12);
        const std::uint32_t tx = read_be32(data.data() + 16);
        std::cout << "  ║  Originate: " << orig << " ms\n";
        std::cout << "  ║  Receive  : " << rx << " ms\n";
        std::cout << "  ║  Transmit : " << tx << " ms\n";
      }
      break;

    default:
      if (data.size() > 8) {
        std::cout << "  ║  Payload  (" << (data.size() - 8) << " bytes):\n";
        hex_dump(data.subspan(8), 32, "  ║    ");
      }
      break;
  }
  std::cout << "  ╚═══════════════════════════════════════════════════╝\n";
}

// ─── ICMPv6 decoder ──────────────────────────────────────────────────────────

void decode_icmpv6(std::span<const std::uint8_t> data) {
  if (data.size() < 4) {
    std::cout << "  [ICMPv6 too short]\n";
    return;
  }
  const std::uint8_t type = data[0];
  const std::uint8_t code = data[1];
  const std::uint16_t csum = read_be16(data.data() + 2);

  std::cout << "  ╔═ ICMPv6 ══════════════════════════════════════════╗\n";
  std::cout << "  ║  Type     : " << static_cast<int>(type) << "  ("
            << icmp6_type_name(type) << ")\n";
  std::cout << "  ║  Code     : " << static_cast<int>(code) << "\n";
  std::cout << "  ║  Checksum : " << hex_word(csum) << "\n";

  switch (type) {
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
      if (data.size() >= 8) {
        const std::uint16_t id = read_be16(data.data() + 4);
        const std::uint16_t seq = read_be16(data.data() + 6);
        std::cout << "  ║  ID       : " << id << "\n";
        std::cout << "  ║  Sequence : " << seq << "\n";
      }
      break;

    case ICMP6_DST_UNREACH:
      std::cout << "  ║  Reason   : ";
      switch (code) {
        case ICMP6_DST_UNREACH_NOROUTE:
          std::cout << "No Route to Destination\n";
          break;
        case ICMP6_DST_UNREACH_ADMIN:
          std::cout << "Admin Prohibited\n";
          break;
        case ICMP6_DST_UNREACH_BEYONDSCOPE:
          std::cout << "Beyond Scope of Source\n";
          break;
        case ICMP6_DST_UNREACH_ADDR:
          std::cout << "Address Unreachable\n";
          break;
        case ICMP6_DST_UNREACH_NOPORT:
          std::cout << "Port Unreachable\n";
          break;
        default:
          std::cout << "Unknown (" << static_cast<int>(code) << ")\n";
          break;
      }
      break;

    case ICMP6_PACKET_TOO_BIG:
      if (data.size() >= 8) {
        const std::uint32_t mtu = read_be32(data.data() + 4);
        std::cout << "  ║  MTU      : " << mtu << "\n";
      }
      break;

    case ICMP6_TIME_EXCEEDED:
      std::cout << "  ║  Reason   : "
                << (code == ICMP6_TIME_EXCEED_TRANSIT
                        ? "Hop Limit Exceeded in Transit"
                    : code == ICMP6_TIME_EXCEED_REASSEMBLY
                        ? "Fragment Reassembly Timeout"
                        : "Unknown")
                << " (" << static_cast<int>(code) << ")\n";
      break;

    case ND_ROUTER_SOLICIT:
    case ND_ROUTER_ADVERT:
    case ND_NEIGHBOR_SOLICIT:
    case ND_NEIGHBOR_ADVERT:
    case ND_REDIRECT:
      if (data.size() >= 8) {
        if ((type == ND_NEIGHBOR_SOLICIT || type == ND_NEIGHBOR_ADVERT ||
             type == ND_REDIRECT) &&
            data.size() >= 24)
          std::cout << "  ║  Target   : " << ipv6_to_str(data.data() + 8)
                    << "\n";
        if (type == ND_ROUTER_ADVERT && data.size() >= 16) {
          std::cout << "  ║  Hop Limit: " << static_cast<int>(data[4]) << "\n";
          std::cout << "  ║  Flags    : M=" << ((data[5] >> 7) & 1)
                    << " O=" << ((data[5] >> 6) & 1) << "\n";
          const std::uint16_t lifetime = read_be16(data.data() + 6);
          std::cout << "  ║  Lifetime : " << lifetime << " s\n";
        }
      }
      break;

    default:
      if (data.size() > 4) {
        std::cout << "  ║  Payload  (" << (data.size() - 4) << " bytes):\n";
        hex_dump(data.subspan(4), 32, "  ║    ");
      }
      break;
  }
  std::cout << "  ╚═══════════════════════════════════════════════════╝\n";
}

// ─── Generic upper-layer summary ─────────────────────────────────────────────

void print_upper_layer_summary(std::uint8_t proto,
                               std::span<const std::uint8_t> data) {
  std::cout << "  ┌─ " << ip_proto_name(proto) << " (proto "
            << static_cast<int>(proto) << ") payload"
            << " ─────────────────────\n";

  if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_SCTP) &&
      data.size() >= 4) {
    const std::uint16_t sport = read_be16(data.data());
    const std::uint16_t dport = read_be16(data.data() + 2);
    std::cout << "  │  Src Port : " << sport << "\n";
    std::cout << "  │  Dst Port : " << dport << "\n";
  }
  if (proto == IPPROTO_IGMP && data.size() >= 8) {
    std::cout << "  │  Type     : " << hex_byte(data[0]) << "\n";
    std::cout << "  │  Group    : "
              << ipv4_to_str(read_unaligned<std::uint32_t>(data.data() + 4))
              << "\n";
  }
  if (proto == IPPROTO_GRE && data.size() >= 4) {
    const std::uint16_t flags = read_be16(data.data());
    const std::uint16_t ptype = read_be16(data.data() + 2);
    std::cout << "  │  Flags    : " << hex_word(flags) << "\n";
    std::cout << "  │  Protocol : " << hex_word(ptype) << "\n";
  }
  if (!data.empty()) {
    std::cout << "  │  Raw (" << data.size() << " bytes):\n";
    hex_dump(data, 32, "  │    ");
  }
  std::cout << "  └──────────────────────────────────────────────────\n";
}

// ─── IPv6 extension header walker ────────────────────────────────────────────

struct ExtWalkResult {
  std::uint8_t final_proto = 0;  ///< Upper-layer protocol after all extensions
  std::span<const std::uint8_t> payload;
  bool has_routing = false;
  bool has_fragment = false;
  std::uint32_t frag_id = 0;
  std::uint16_t frag_offset = 0;  ///< In bytes
  bool frag_more = false;
  std::vector<std::uint8_t> ext_chain;  ///< Ordered list of ext header types
};

[[nodiscard]] ExtWalkResult walk_ipv6_extensions(
    std::uint8_t next_hdr, std::span<const std::uint8_t> data) {
  ExtWalkResult r;
  r.final_proto = next_hdr;
  r.payload = data;

  constexpr auto is_ext = [](std::uint8_t t) noexcept {
    return t == IPPROTO_HOPOPTS || t == IPPROTO_ROUTING ||
           t == IPPROTO_FRAGMENT || t == IPPROTO_DSTOPTS || t == IPPROTO_MH ||
           t == IPPROTO_NONE;
  };

  std::size_t off = 0;
  while (is_ext(next_hdr) && off < data.size()) {
    r.ext_chain.push_back(next_hdr);

    if (next_hdr == IPPROTO_FRAGMENT) {
      if (off + 8 > data.size()) break;
      const std::uint16_t fo_m = read_be16(data.data() + off + 2);
      r.has_fragment = true;
      r.frag_offset = static_cast<std::uint16_t>((fo_m >> 3) * 8);
      r.frag_more = (fo_m & 0x01) != 0;
      r.frag_id = read_be32(data.data() + off + 4);
      next_hdr = data[off];
      off += 8;
    } else if (next_hdr == IPPROTO_NONE) {
      off = data.size();
      break;
    } else {
      if (off + 2 > data.size()) break;
      const std::uint8_t ext_len = data[off + 1];
      const std::size_t hdr_sz = (static_cast<std::size_t>(ext_len) + 1) * 8;

      if (next_hdr == IPPROTO_ROUTING) r.has_routing = true;

      next_hdr = data[off];
      off += hdr_sz;
    }
  }

  r.final_proto = next_hdr;
  r.payload =
      (off < data.size()) ? data.subspan(off) : std::span<const std::uint8_t>{};
  return r;
}

// ─── IPv4 decoder ────────────────────────────────────────────────────────────

void decode_ipv4(std::span<const std::uint8_t> data) {
  if (data.size() < 20) {
    std::cout << "  [IPv4 too short]\n";
    return;
  }

  iphdr iph{};
  std::memcpy(&iph, data.data(), sizeof(iph));

  const std::uint8_t ihl = iph.ihl * 4;
  const std::uint8_t tos = iph.tos;
  const std::uint8_t dscp = tos >> 2;
  const std::uint8_t ecn = tos & 0x03;
  const std::uint16_t tot_len = ntohs(iph.tot_len);
  const std::uint16_t id = ntohs(iph.id);
  const std::uint16_t frag_off = ntohs(iph.frag_off);
  const bool flag_df = (frag_off & IP_DF) != 0;
  const bool flag_mf = (frag_off & IP_MF) != 0;
  const std::uint16_t offset = (frag_off & IP_OFFMASK) * 8;
  const std::uint8_t ttl = iph.ttl;
  const std::uint8_t proto = iph.protocol;
  const std::uint16_t csum = ntohs(iph.check);

  std::cout << "\n┌─ Frame #" << ++g_frame_count
            << " ────────────────────────────────────────────────\n";
  std::cout << "│ ╔═ IPv4 Header ══════════════════════════════════════════╗\n";
  std::cout << "│ ║  Version     : 4\n";
  std::cout << "│ ║  IHL         : " << static_cast<int>(ihl) << " bytes ("
            << static_cast<int>(iph.ihl) << " DWORDs)\n";
  std::cout << "│ ║  TOS/DSCP    : " << hex_byte(tos)
            << "  DSCP=" << static_cast<int>(dscp) << " (" << dscp_name(dscp)
            << ")" << "  ECN=" << static_cast<int>(ecn) << "\n";
  std::cout << "│ ║  Total Len   : " << tot_len << " bytes\n";

  std::cout << "│ ║  ID          : " << hex_word(id) << "\n";
  std::cout << "│ ║  Flags       : DF=" << flag_df << " MF=" << flag_mf << "\n";
  std::cout << "│ ║  Frag Offset : " << offset << " bytes"
            << (offset == 0 && !flag_mf  ? " [Not Fragmented]"
                : offset == 0 && flag_mf ? " [First Fragment]"
                : !flag_mf               ? " [Last Fragment]"
                                         : " [Middle Fragment]")
            << "\n";
  if (flag_df && !flag_mf && offset == 0)
    std::cout << "│ ║  [DF set – Path MTU Discovery in use]\n";

  std::cout << "│ ║  TTL         : " << static_cast<int>(ttl);
  if (ttl <= 1)
    std::cout << "  ⚠ EXPIRES NEXT HOP";
  else if (ttl < 10)
    std::cout << "  (low – approaching expiry)";
  std::cout << "\n";
  std::cout << "│ ║  Protocol    : " << static_cast<int>(proto) << "  ("
            << ip_proto_name(proto) << ")\n";
  std::cout << "│ ║  Checksum    : " << hex_word(csum) << "\n";
  std::cout << "│ ║  Src IP      : " << ipv4_to_str(iph.saddr) << "\n";
  std::cout << "│ ║  Dst IP      : " << ipv4_to_str(iph.daddr) << "\n";

  if (ihl > 20 && ihl <= data.size()) {
    std::cout << "│ ║  Options     : (" << static_cast<int>(ihl - 20)
              << " bytes)\n";
    decode_ipv4_options(data.subspan(20, ihl - 20));
  }

  std::cout << "│ ╚═══════════════════════════════════════════════════════╝\n";

  if (ihl > data.size()) {
    std::cout << "  [Truncated – IHL beyond buffer]\n";
    return;
  }

  std::size_t pay_len = (tot_len > ihl) ? (tot_len - ihl) : 0;
  pay_len = std::min(pay_len, data.size() - ihl);
  const auto payload = data.subspan(ihl, pay_len);

  if (offset > 0) {
    std::cout << "│  [Fragment data – upper-layer header not available]\n";
    hex_dump(payload, 32, "│    ");
    std::cout << "└────────────────────────────────────────────────────────\n";
    return;
  }

  switch (proto) {
    case IPPROTO_ICMP:
      decode_icmpv4(payload);
      break;
    default:
      print_upper_layer_summary(proto, payload);
      break;
  }
  std::cout << "└────────────────────────────────────────────────────────\n";
}

// ─── IPv6 decoder ────────────────────────────────────────────────────────────

void decode_ipv6(std::span<const std::uint8_t> data) {
  if (data.size() < 40) {
    std::cout << "  [IPv6 too short]\n";
    return;
  }

  ip6_hdr ip6h{};
  std::memcpy(&ip6h, data.data(), sizeof(ip6h));

  const std::uint32_t vtc_flow = ntohl(ip6h.ip6_flow);
  const std::uint8_t version = (vtc_flow >> 28) & 0x0F;
  const std::uint8_t tc = (vtc_flow >> 20) & 0xFF;
  const std::uint8_t dscp = tc >> 2;
  const std::uint8_t ecn = tc & 0x03;
  const std::uint32_t flow_lbl = vtc_flow & 0x000FFFFF;
  const std::uint16_t pay_len = ntohs(ip6h.ip6_plen);
  const std::uint8_t next_hdr = ip6h.ip6_nxt;
  const std::uint8_t hop_lim = ip6h.ip6_hlim;

  std::cout << "\n┌─ Frame #" << ++g_frame_count
            << " ────────────────────────────────────────────────\n";
  std::cout << "│ ╔═ IPv6 Header ══════════════════════════════════════════╗\n";
  std::cout << "│ ║  Version     : " << static_cast<int>(version) << "\n";
  std::cout << "│ ║  Traffic Cls : " << hex_byte(tc)
            << "  DSCP=" << static_cast<int>(dscp) << " (" << dscp_name(dscp)
            << ")" << "  ECN=" << static_cast<int>(ecn) << "\n";
  std::cout << "│ ║  Flow Label  : 0x" << std::hex << std::setw(5)
            << std::setfill('0') << flow_lbl << std::dec
            << (flow_lbl ? "" : "  [No Flow]") << "\n";
  std::cout << "│ ║  Payload Len : " << pay_len << " bytes\n";
  std::cout << "│ ║  Next Header : " << static_cast<int>(next_hdr) << "  ("
            << (next_hdr < 143 ? ip_proto_name(next_hdr)
                               : ipv6_ext_name(next_hdr))
            << ")\n";
  std::cout << "│ ║  Hop Limit   : " << static_cast<int>(hop_lim);
  if (hop_lim <= 1)
    std::cout << "  ⚠ EXPIRES NEXT HOP";
  else if (hop_lim < 10)
    std::cout << "  (low)";
  std::cout << "\n";
  std::cout << "│ ║  Src IP      : " << ipv6_to_str(&ip6h.ip6_src) << "\n";
  std::cout << "│ ║  Dst IP      : " << ipv6_to_str(&ip6h.ip6_dst) << "\n";

  const std::size_t ext_len =
      std::min(static_cast<std::size_t>(pay_len), data.size() - 40);
  const ExtWalkResult ext =
      walk_ipv6_extensions(next_hdr, data.subspan(40, ext_len));

  if (!ext.ext_chain.empty()) {
    std::cout << "│ ║  Ext Headers : ";
    for (std::size_t i = 0; i < ext.ext_chain.size(); ++i) {
      if (i) std::cout << " → ";
      std::cout << ipv6_ext_name(ext.ext_chain[i]);
    }
    std::cout << "\n";
  }

  if (ext.has_routing)
    std::cout << "│ ║  [Routing extension header present – "
                 "source routing or segment routing]\n";

  if (ext.has_fragment) {
    std::cout << "│ ║  ── Fragment Header ──────────────────────────────\n";
    std::cout << "│ ║    Fragment ID     : 0x" << std::hex << ext.frag_id
              << std::dec << "\n";
    std::cout << "│ ║    Fragment Offset : " << ext.frag_offset << " bytes"
              << (ext.frag_offset == 0 && ext.frag_more    ? " [First Fragment]"
                  : ext.frag_offset == 0 && !ext.frag_more ? " [Not Fragmented]"
                  : !ext.frag_more                         ? " [Last Fragment]"
                                   : " [Middle Fragment]")
              << "\n";
    std::cout << "│ ║    More Fragments  : " << (ext.frag_more ? "Yes" : "No")
              << "\n";
  }

  std::cout << "│ ╚═══════════════════════════════════════════════════════╝\n";

  if (ext.has_fragment && ext.frag_offset > 0) {
    std::cout << "│  [Fragment data – upper-layer header not available]\n";
    hex_dump(ext.payload, 32, "│    ");
    std::cout << "└────────────────────────────────────────────────────────\n";
    return;
  }

  switch (ext.final_proto) {
    case IPPROTO_ICMPV6:
      decode_icmpv6(ext.payload);
      break;
    default:
      print_upper_layer_summary(ext.final_proto, ext.payload);
      break;
  }
  std::cout << "└────────────────────────────────────────────────────────\n";
}

// ─── Ethernet frame dispatcher ───────────────────────────────────────────────

void dispatch_ethernet(std::span<const std::uint8_t> frame) {
  if (frame.size() < 14) return;

  const auto dst = frame.subspan<0, kMacAddrLen>();
  const auto src = frame.subspan<kMacAddrLen, kMacAddrLen>();
  std::uint16_t eth = read_be16(frame.data() + 12);

  std::size_t l3_offset = 14;

  // 802.1Q VLAN tag stripping
  if (eth == 0x8100 || eth == 0x88A8) {
    if (frame.size() < 18) return;
    eth = read_be16(frame.data() + 16);
    l3_offset = 18;
  }

  if (eth != ETH_P_IP && eth != ETH_P_IPV6) {
    std::cout << "\n[EtherType " << hex_word(eth) << " – Src "
              << mac_to_str(src) << " → Dst " << mac_to_str(dst)
              << " | not IPv4/IPv6, skipping L3 decode]\n";
    return;
  }

  const auto l3 = frame.subspan(l3_offset);

  if (eth == ETH_P_IP)
    decode_ipv4(l3);
  else
    decode_ipv6(l3);
}

}  // namespace

// ─── Main ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
  const char* iface = (argc >= 2) ? argv[1] : "eth0";

  std::cout << "OSI Layer 3 – Network Layer Packet Reader\n"
            << "Interface : " << iface << "\n"
            << "Protocols : IPv4 (full) · IPv6 (full) · ICMPv4 · ICMPv6\n"
            << "            TCP/UDP/IGMP/GRE/OSPF/SCTP (summary)\n"
            << "Press Ctrl+C to stop.\n";

  const int sock = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    std::perror("socket");
    std::cerr << "Hint: run as root or grant CAP_NET_RAW\n";
    return 1;
  }

  ifreq ifr{};
  std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  if (::ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    std::perror("ioctl(SIOCGIFINDEX)");
    ::close(sock);
    return 1;
  }

  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = ifr.ifr_ifindex;

  if (::bind(sock, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
    std::perror("bind");
    ::close(sock);
    return 1;
  }

  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  auto buf = std::make_unique<std::array<std::uint8_t, kBufferSize>>();
  sockaddr_ll sender{};
  socklen_t sender_len = sizeof(sender);

  while (g_running.load(std::memory_order_relaxed)) {
    const ssize_t n =
        ::recvfrom(sock, buf->data(), buf->size(), 0,
                   reinterpret_cast<sockaddr*>(&sender), &sender_len);
    if (n < 0) {
      if (g_running.load(std::memory_order_relaxed)) std::perror("recvfrom");
      break;
    }
    dispatch_ethernet(std::span<const std::uint8_t>(
        buf->data(), static_cast<std::size_t>(n)));
  }

  ::close(sock);
  std::cout << "\nCaptured " << g_frame_count << " L3 packet(s). Goodbye.\n";
  return 0;
}
