#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <bit>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>

namespace {

// ─── Constants ─────────────────────────────────────────────────────────────

constexpr std::size_t kBufferSize = 65536;
constexpr std::size_t kMacAddrLen = 6;
constexpr std::size_t kEtherHdrMin = 14;  // dst(6) + src(6) + type(2)
constexpr std::size_t kVlanTagLen = 4;
constexpr std::uint16_t kEtherType8021Q = 0x8100;
constexpr std::uint16_t kEtherType8021AD = 0x88A8;
constexpr std::size_t kHexDumpDefaultMax = 64;

using MacAddr = std::array<std::uint8_t, kMacAddrLen>;

// ─── Globals ───────────────────────────────────────────────────────────────

std::atomic<bool> g_running{true};
std::uint64_t g_frame_count = 0;

extern "C" void signal_handler(int /*sig*/) {
  g_running.store(false, std::memory_order_relaxed);
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Read a big-endian 16-bit value from an unaligned byte span.
[[nodiscard]] std::uint16_t read_be16(std::span<const std::uint8_t, 2> bytes) {
  std::uint16_t net{};
  std::memcpy(&net, bytes.data(), sizeof(net));
  return ntohs(net);
}

/// Format a 6-byte MAC address as "AA:BB:CC:DD:EE:FF".
[[nodiscard]] std::string mac_to_string(const MacAddr& mac) {
  std::ostringstream oss;
  oss << std::hex << std::uppercase << std::setfill('0');
  for (std::size_t i = 0; i < mac.size(); ++i) {
    if (i != 0) oss << ':';
    oss << std::setw(2) << static_cast<int>(mac[i]);
  }
  return std::move(oss).str();
}

/// Resolve a numeric EtherType to a human-readable name.
[[nodiscard]] std::string ethertype_name(std::uint16_t ethertype) {
  switch (ethertype) {
    case ETH_P_IP:       return "IPv4";
    case ETH_P_IPV6:     return "IPv6";
    case ETH_P_ARP:      return "ARP";
    case ETH_P_RARP:     return "RARP";
    case ETH_P_8021Q:    return "802.1Q VLAN";
    case ETH_P_LLDP:     return "LLDP";
    case ETH_P_MPLS_UC:  return "MPLS Unicast";
    case ETH_P_MPLS_MC:  return "MPLS Multicast";
    case ETH_P_8021AD:   return "802.1ad QinQ";
    default: {
      std::ostringstream oss;
      oss << "Unknown: 0x" << std::hex << std::uppercase << ethertype;
      return std::move(oss).str();
    }
  }
}

/// Hex-dump up to `max_bytes` bytes from `data`, 16 bytes per line.
void hex_dump(std::span<const std::uint8_t> data,
              std::size_t max_bytes = kHexDumpDefaultMax) {
  const std::size_t limit = std::min(data.size(), max_bytes);
  for (std::size_t i = 0; i < limit; i += 16) {
    std::cout << "    " << std::hex << std::setw(4) << std::setfill('0') << i
              << "  ";
    const std::size_t row_end = std::min(i + 16, limit);
    for (std::size_t j = i; j < row_end; ++j) {
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(data[j]) << ' ';
    }
    std::cout << '\n';
  }
  std::cout << std::dec;
  if (data.size() > max_bytes) {
    std::cout << "    ... (" << (data.size() - max_bytes)
              << " more bytes)\n";
  }
}

// ─── Frame parser ──────────────────────────────────────────────────────────

struct EthernetFrame {
  MacAddr dst_mac{};
  MacAddr src_mac{};
  std::uint16_t ethertype{};  ///< After VLAN tag stripping (if any)
  bool has_vlan_tag{false};
  std::uint16_t vlan_id{0};        ///< Valid when has_vlan_tag == true
  std::uint8_t vlan_priority{0};   ///< PCP bits (0-7)
  std::span<const std::uint8_t> payload;
};

/// Parse a raw Ethernet II / 802.1Q frame.
/// Returns std::nullopt if the buffer is too short.
[[nodiscard]] std::optional<EthernetFrame> parse_ethernet_frame(
    std::span<const std::uint8_t> buf) {
  if (buf.size() < kEtherHdrMin) return std::nullopt;

  EthernetFrame frame{};
  std::memcpy(frame.dst_mac.data(), buf.data(), kMacAddrLen);
  std::memcpy(frame.src_mac.data(), buf.data() + kMacAddrLen, kMacAddrLen);

  std::uint16_t type_or_len = read_be16(buf.subspan<12, 2>());
  std::size_t offset = kEtherHdrMin;

  // 802.1Q VLAN tag (0x8100) or QinQ (0x88A8)
  if (type_or_len == kEtherType8021Q || type_or_len == kEtherType8021AD) {
    if (buf.size() < offset + kVlanTagLen) return std::nullopt;
    const std::uint16_t tci =
        read_be16(buf.subspan(offset).first<2>());
    frame.has_vlan_tag = true;
    frame.vlan_priority = static_cast<std::uint8_t>((tci >> 13) & 0x07);
    frame.vlan_id = tci & 0x0FFF;
    offset += 2;
    type_or_len = read_be16(buf.subspan(offset).first<2>());
    offset += 2;
  }

  frame.ethertype = type_or_len;
  frame.payload = buf.subspan(offset);
  return frame;
}

// ─── Display ───────────────────────────────────────────────────────────────

void print_frame(const EthernetFrame& f, std::size_t raw_len) {
  ++g_frame_count;
  std::cout << "\n┌─ Frame #" << g_frame_count
            << " ─────────────────────────────────────────\n"
            << "│ Dst MAC   : " << mac_to_string(f.dst_mac) << '\n'
            << "│ Src MAC   : " << mac_to_string(f.src_mac) << '\n';

  if (f.has_vlan_tag) {
    std::cout << "│ VLAN      : id=" << f.vlan_id
              << "  priority=" << static_cast<int>(f.vlan_priority) << '\n';
  }

  std::cout << "│ EtherType : 0x" << std::hex << std::uppercase << std::setw(4)
            << std::setfill('0') << f.ethertype << std::dec << "  ("
            << ethertype_name(f.ethertype) << ")\n"
            << "│ Total len : " << raw_len << " bytes"
            << "   Payload: " << f.payload.size() << " bytes\n"
            << "│ Payload (hex, first " << kHexDumpDefaultMax << " bytes):\n";
  hex_dump(f.payload);
  std::cout << "└─────────────────────────────────────────────────────\n";
}

// ─── RAII socket ───────────────────────────────────────────────────────────

class UniqueFd {
 public:
  UniqueFd() = default;
  explicit UniqueFd(int fd) noexcept : fd_{fd} {}
  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;
  UniqueFd(UniqueFd&& other) noexcept : fd_{other.release()} {}
  UniqueFd& operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
      reset(other.release());
    }
    return *this;
  }
  ~UniqueFd() { reset(); }

  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

  int release() noexcept {
    int old = fd_;
    fd_ = -1;
    return old;
  }
  void reset(int fd = -1) noexcept {
    if (fd_ >= 0) ::close(fd_);
    fd_ = fd;
  }

 private:
  int fd_{-1};
};

}  // namespace

// ─── Main ──────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
  const std::string_view iface =
      (argc >= 2) ? std::string_view{argv[1]} : std::string_view{"eth0"};

  std::cout << "OSI Layer 2 - Data Link Frame Reader\n"
            << "Interface : " << iface << "\n"
            << "Press Ctrl+C to stop.\n\n";

  // --- Create a raw socket that captures ALL Ethernet frames ---
  UniqueFd sock{::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))};
  if (!sock.valid()) {
    std::perror("socket");
    std::cerr << "Hint: run as root or grant CAP_NET_RAW\n";
    return 1;
  }

  // --- Bind to the requested interface ---
  ifreq ifr{};
  const std::size_t name_len =
      std::min(iface.size(), static_cast<std::size_t>(IFNAMSIZ - 1));
  std::memcpy(ifr.ifr_name, iface.data(), name_len);
  ifr.ifr_name[name_len] = '\0';

  if (::ioctl(sock.get(), SIOCGIFINDEX, &ifr) < 0) {
    std::perror("ioctl(SIOCGIFINDEX)");
    return 1;
  }

  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = ifr.ifr_ifindex;

  if (::bind(sock.get(), std::bit_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
    std::perror("bind");
    return 1;
  }

  // --- Set up graceful Ctrl+C shutdown ---
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  // --- Capture loop ---
  std::array<std::uint8_t, kBufferSize> buf{};
  sockaddr_ll sender{};
  socklen_t sender_len = sizeof(sender);

  while (g_running.load(std::memory_order_relaxed)) {
    const ssize_t n = ::recvfrom(sock.get(), buf.data(), buf.size(), 0,
                                 std::bit_cast<sockaddr*>(&sender),
                                 &sender_len);
    if (n < 0) {
      if (g_running.load(std::memory_order_relaxed)) std::perror("recvfrom");
      break;
    }

    const std::span<const std::uint8_t> view{buf.data(),
                                             static_cast<std::size_t>(n)};
    if (auto frame = parse_ethernet_frame(view)) {
      print_frame(*frame, static_cast<std::size_t>(n));
    }
  }

  std::cout << "\nCaptured " << g_frame_count << " frame(s). Goodbye.\n";
  return 0;
}
