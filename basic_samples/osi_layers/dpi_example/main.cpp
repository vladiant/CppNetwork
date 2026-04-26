// Minimal Deep Packet Inspection (DPI) example.
//
// Captures Ethernet frames via an AF_PACKET raw socket, parses
// Ethernet -> IPv4 -> TCP, maintains a per-flow state keyed by the
// classic 5-tuple, and runs a tiny payload classifier (HTTP / TLS).
//
// Run with CAP_NET_RAW (e.g. `sudo ./dpi_example` or
// `sudo setcap cap_net_raw,cap_net_admin=eip ./dpi_example`).

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>

namespace {

// ---------------------------------------------------------------------------
// Flow identification
// ---------------------------------------------------------------------------

struct FlowKey {
  uint32_t src_ip{};
  uint32_t dst_ip{};
  uint16_t src_port{};
  uint16_t dst_port{};
  uint8_t protocol{};

  bool operator==(const FlowKey&) const = default;
};

struct FlowKeyHash {
  size_t operator()(const FlowKey& k) const noexcept {
    constexpr size_t kGold = 0x9e3779b97f4a7c15ULL;
    auto mix = [&](size_t h, size_t v) {
      return h ^ (v + kGold + (h << 6) + (h >> 2));
    };
    size_t h = std::hash<uint32_t>{}(k.src_ip);
    h = mix(h, std::hash<uint32_t>{}(k.dst_ip));
    h = mix(h, std::hash<uint16_t>{}(k.src_port));
    h = mix(h, std::hash<uint16_t>{}(k.dst_port));
    h = mix(h, std::hash<uint8_t>{}(k.protocol));
    return h;
  }
};

// ---------------------------------------------------------------------------
// Per-flow state and a very small L7 classifier
// ---------------------------------------------------------------------------

enum class L7Protocol { Unknown, HTTP, TLS };

const char* to_string(L7Protocol p) {
  switch (p) {
    case L7Protocol::HTTP: return "HTTP";
    case L7Protocol::TLS:  return "TLS";
    default:               return "Unknown";
  }
}

struct FlowState {
  uint64_t packets{0};
  uint64_t bytes{0};
  uint32_t last_seq{0};
  L7Protocol l7{L7Protocol::Unknown};

  // Inspect first payload bytes to guess the L7 protocol.
  static L7Protocol classify(const uint8_t* payload, size_t len) {
    if (len == 0) return L7Protocol::Unknown;

    // TLS record: ContentType=Handshake(0x16), Version major=0x03, minor 1..4.
    if (len >= 5 && payload[0] == 0x16 && payload[1] == 0x03 &&
        payload[2] <= 0x04) {
      return L7Protocol::TLS;
    }

    static constexpr std::string_view kPrefixes[] = {
        "GET ",    "POST ",   "HEAD ",    "PUT ",   "DELETE ",
        "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "HTTP/1."};
    const std::string_view sv(reinterpret_cast<const char*>(payload),
                              std::min<size_t>(len, 16));
    for (auto p : kPrefixes) {
      if (sv.starts_with(p)) return L7Protocol::HTTP;
    }
    return L7Protocol::Unknown;
  }

  void update(uint32_t seq, const uint8_t* payload, size_t pay_len) {
    ++packets;
    bytes += pay_len;
    last_seq = seq;
    if (l7 == L7Protocol::Unknown && pay_len > 0) {
      l7 = classify(payload, pay_len);
    }
  }
};

std::unordered_map<FlowKey, FlowState, FlowKeyHash> g_flow_table;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string ip_to_string(uint32_t ip_host_order) {
  in_addr a{};
  a.s_addr = htonl(ip_host_order);
  char buf[INET_ADDRSTRLEN]{};
  inet_ntop(AF_INET, &a, buf, sizeof(buf));
  return buf;
}

void log_flow_event(const char* tag, const FlowKey& k, const FlowState& s) {
  std::cout << '[' << tag << "] " << ip_to_string(k.src_ip) << ':' << k.src_port
            << " -> " << ip_to_string(k.dst_ip) << ':' << k.dst_port
            << "  L7=" << to_string(s.l7) << '\n';
}

// ---------------------------------------------------------------------------
// Packet parsing
// ---------------------------------------------------------------------------

// One's-complement sum over `len` bytes starting at `data`, folded to 16 bits.
// Used to verify the IPv4 header checksum (RFC 1071). A correct header sums
// to 0xFFFF including the `check` field itself.
uint16_t ipv4_header_checksum(const uint8_t* data, size_t len) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < len; i += 2) {
    uint16_t word = 0;
    std::memcpy(&word, data + i, sizeof(word));
    sum += ntohs(word);
  }
  if (len & 1) sum += static_cast<uint32_t>(data[len - 1]) << 8;
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

bool parse_packet(const uint8_t* buf, size_t len) {
  if (len < sizeof(ethhdr)) return false;
  const auto* eth = reinterpret_cast<const ethhdr*>(buf);
  uint16_t ether_type = ntohs(eth->h_proto);

  // Handle a single 802.1Q VLAN tag.
  size_t ip_offset = sizeof(ethhdr);
  if (ether_type == ETH_P_8021Q) {
    if (len < ip_offset + 4) return false;
    uint16_t inner_type_be = 0;
    std::memcpy(&inner_type_be, buf + ip_offset + 2, sizeof(inner_type_be));
    ether_type = ntohs(inner_type_be);
    ip_offset += 4;
  }
  if (ether_type != ETH_P_IP) return false;

  // IPv4
  if (len < ip_offset + sizeof(iphdr)) return false;
  const auto* ip = reinterpret_cast<const iphdr*>(buf + ip_offset);
  if (ip->version != 4) return false;
  const size_t ihl = static_cast<size_t>(ip->ihl) * 4;
  if (ihl < sizeof(iphdr) || len < ip_offset + ihl) return false;

  // Verify the IPv4 header checksum before trusting any other header field.
  // Note: AF_PACKET often delivers locally generated frames with check==0
  // (TX checksum offload defers the computation to the NIC), so a 0 value
  // is treated as "not computed" rather than invalid.
  if (ip->check != 0) {
    const uint16_t computed = ipv4_header_checksum(buf + ip_offset, ihl);
    if (computed != 0) return false;
  }

  const uint32_t src_ip = ntohl(ip->saddr);
  const uint32_t dst_ip = ntohl(ip->daddr);
  const uint16_t total = ntohs(ip->tot_len);
  if (total < ihl) return false;
  // tot_len is attacker-controlled; ensure it fits in the captured buffer
  // before using it to derive payload length below.
  if (len < ip_offset + total) return false;
  if (ip->protocol != IPPROTO_TCP) return false;

  // TCP
  const size_t tcp_offset = ip_offset + ihl;
  if (len < tcp_offset + sizeof(tcphdr)) return false;
  const auto* tcp = reinterpret_cast<const tcphdr*>(buf + tcp_offset);
  const size_t doff = static_cast<size_t>(tcp->doff) * 4;
  if (doff < sizeof(tcphdr) || len < tcp_offset + doff) return false;

  const uint16_t sport = ntohs(tcp->source);
  const uint16_t dport = ntohs(tcp->dest);
  const uint32_t seq = ntohl(tcp->seq);

  // Payload
  const size_t l4_total = total - ihl;
  const size_t pay_len = (l4_total > doff) ? (l4_total - doff) : 0;
  const uint8_t* payload = buf + tcp_offset + doff;

  FlowKey key{src_ip, dst_ip, sport, dport, IPPROTO_TCP};
  auto [it, inserted] = g_flow_table.try_emplace(key);
  const L7Protocol prev = it->second.l7;
  it->second.update(seq, payload, pay_len);

  if (inserted) {
    log_flow_event("flow", key, it->second);
  } else if (prev == L7Protocol::Unknown &&
             it->second.l7 != L7Protocol::Unknown) {
    log_flow_event("classified", key, it->second);
  }
  return true;
}

// ---------------------------------------------------------------------------
// Capture loop
// ---------------------------------------------------------------------------

std::atomic<bool> g_stop{false};

void on_signal(int) { g_stop.store(true, std::memory_order_relaxed); }

int run_capture() {
  // AF_PACKET / SOCK_RAW delivers full Ethernet frames from every interface.
  const int fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    std::perror("socket(AF_PACKET)");
    std::cerr << "Hint: requires CAP_NET_RAW (run as root or setcap).\n";
    return 1;
  }

  std::cout << "DPI capture started. Press Ctrl+C to stop.\n";

  uint8_t buf[65536];
  uint64_t total_packets = 0;
  uint64_t parsed = 0;

  while (!g_stop.load(std::memory_order_relaxed)) {
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      std::perror("recv");
      break;
    }
    ++total_packets;
    if (parse_packet(buf, static_cast<size_t>(n))) ++parsed;
  }

  ::close(fd);

  std::cout << "\n--- Capture summary ---\n"
            << "packets seen   : " << total_packets << '\n'
            << "TCP/IPv4 parsed: " << parsed << '\n'
            << "flows tracked  : " << g_flow_table.size() << "\n\n";

  size_t shown = 0;
  for (const auto& [k, s] : g_flow_table) {
    if (shown++ == 20) {
      std::cout << "... (" << g_flow_table.size() - 20 << " more)\n";
      break;
    }
    std::cout << std::left << std::setw(22)
              << (ip_to_string(k.src_ip) + ':' + std::to_string(k.src_port))
              << " -> " << std::setw(22)
              << (ip_to_string(k.dst_ip) + ':' + std::to_string(k.dst_port))
              << "  pkts=" << std::setw(6) << s.packets
              << " bytes=" << std::setw(8) << s.bytes
              << " L7=" << to_string(s.l7) << '\n';
  }
  return 0;
}

}  // namespace

int main() {
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  return run_capture();
}
