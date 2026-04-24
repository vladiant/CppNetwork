#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

// ─── Constants ───────────────────────────────────────────────────────────────

static constexpr int BUFFER_SIZE = 65536;
static constexpr size_t MAC_ADDR_LEN = 6;

// ─── Globals ─────────────────────────────────────────────────────────────────

static volatile bool g_running = true;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static void signal_handler(int /*sig*/) { g_running = false; }

/// Format a 6-byte MAC address as "AA:BB:CC:DD:EE:FF"
static std::string mac_to_string(const uint8_t* mac) {
  std::ostringstream oss;
  for (size_t i = 0; i < MAC_ADDR_LEN; ++i) {
    if (i) oss << ':';
    oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
        << static_cast<int>(mac[i]);
  }
  return oss.str();
}

/// Resolve a numeric EtherType to a human-readable name
static std::string ethertype_name(uint16_t ethertype) {
  switch (ethertype) {
    case ETH_P_IP:
      return "IPv4";
    case ETH_P_IPV6:
      return "IPv6";
    case ETH_P_ARP:
      return "ARP";
    case ETH_P_RARP:
      return "RARP";
    case ETH_P_8021Q:
      return "802.1Q VLAN";
    case ETH_P_LLDP:
      return "LLDP";
    case ETH_P_MPLS_UC:
      return "MPLS Unicast";
    case ETH_P_MPLS_MC:
      return "MPLS Multicast";
    case ETH_P_8021AD:
      return "802.1ad QinQ";
    default:
      std::ostringstream oss;
      oss << "Unknown: 0x" << std::hex << std::uppercase << ethertype;
      return oss.str();
  }
}

/// Hex-dump `len` bytes from `data`, 16 bytes per line
static void hex_dump(const uint8_t* data, size_t len, size_t max_bytes = 64) {
  size_t limit = std::min(len, max_bytes);
  for (size_t i = 0; i < limit; i += 16) {
    std::cout << "    " << std::hex << std::setw(4) << std::setfill('0') << i
              << "  ";
    for (size_t j = i; j < std::min(i + 16, limit); ++j)
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(data[j]) << ' ';
    std::cout << '\n';
  }
  std::cout << std::dec;
  if (len > max_bytes)
    std::cout << "    ... (" << len - max_bytes << " more bytes)\n";
}

// ─── Frame parser ────────────────────────────────────────────────────────────

struct EthernetFrame {
  uint8_t dst_mac[MAC_ADDR_LEN];
  uint8_t src_mac[MAC_ADDR_LEN];
  uint16_t ethertype;  ///< After VLAN tag stripping (if any)
  bool has_vlan_tag;
  uint16_t vlan_id;       ///< Valid when has_vlan_tag == true
  uint8_t vlan_priority;  ///< PCP bits (0-7)
  const uint8_t* payload;
  size_t payload_len;
};

/// Parse a raw Ethernet II / 802.1Q frame.
/// Returns false if the buffer is too short.
static bool parse_ethernet_frame(const uint8_t* buf, size_t len,
                                 EthernetFrame& frame) {
  constexpr size_t ETHER_HDR_MIN = 14;  // dst(6) + src(6) + type(2)
  if (len < ETHER_HDR_MIN) return false;

  std::memcpy(frame.dst_mac, buf, MAC_ADDR_LEN);
  std::memcpy(frame.src_mac, buf + 6, MAC_ADDR_LEN);

  uint16_t type_or_len = ntohs(*reinterpret_cast<const uint16_t*>(buf + 12));

  size_t offset = 14;

  // 802.1Q VLAN tag (0x8100) or QinQ (0x88A8)
  if (type_or_len == 0x8100 || type_or_len == 0x88A8) {
    if (len < offset + 4) return false;
    uint16_t tci = ntohs(*reinterpret_cast<const uint16_t*>(buf + offset));
    frame.has_vlan_tag = true;
    frame.vlan_priority = (tci >> 13) & 0x07;
    frame.vlan_id = tci & 0x0FFF;
    offset += 2;
    type_or_len = ntohs(*reinterpret_cast<const uint16_t*>(buf + offset));
    offset += 2;
  } else {
    frame.has_vlan_tag = false;
    frame.vlan_id = 0;
    frame.vlan_priority = 0;
  }

  frame.ethertype = type_or_len;
  frame.payload = buf + offset;
  frame.payload_len = (len > offset) ? (len - offset) : 0;
  return true;
}

// ─── Display ─────────────────────────────────────────────────────────────────

static uint64_t g_frame_count = 0;

static void print_frame(const EthernetFrame& f, ssize_t raw_len) {
  ++g_frame_count;
  std::cout << "\n┌─ Frame #" << g_frame_count
            << " ─────────────────────────────────────────\n";
  std::cout << "│ Dst MAC   : " << mac_to_string(f.dst_mac) << '\n';
  std::cout << "│ Src MAC   : " << mac_to_string(f.src_mac) << '\n';

  if (f.has_vlan_tag)
    std::cout << "│ VLAN      : id=" << f.vlan_id
              << "  priority=" << static_cast<int>(f.vlan_priority) << '\n';

  std::cout << "│ EtherType : 0x" << std::hex << std::uppercase << std::setw(4)
            << std::setfill('0') << f.ethertype << std::dec << "  ("
            << ethertype_name(f.ethertype) << ")\n";
  std::cout << "│ Total len : " << raw_len << " bytes"
            << "   Payload: " << f.payload_len << " bytes\n";
  std::cout << "│ Payload (hex, first 64 bytes):\n";
  hex_dump(f.payload, f.payload_len);
  std::cout << "└─────────────────────────────────────────────────────\n";
}

// ─── Main ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
  const char* iface = (argc >= 2) ? argv[1] : "eth0";

  std::cout << "OSI Layer 2 - Data Link Frame Reader\n"
            << "Interface : " << iface << "\n"
            << "Press Ctrl+C to stop.\n\n";

  // --- Create a raw socket that captures ALL Ethernet frames ---
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    perror("socket");
    std::cerr << "Hint: run as root or grant CAP_NET_RAW\n";
    return 1;
  }

  // --- Bind to the requested interface ---
  struct ifreq ifr {};
  std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl(SIOCGIFINDEX)");
    close(sock);
    return 1;
  }

  struct sockaddr_ll sll {};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = ifr.ifr_ifindex;

  if (bind(sock, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
    perror("bind");
    close(sock);
    return 1;
  }

  // --- Set up graceful Ctrl+C shutdown ---
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  // --- Capture loop ---
  std::array<uint8_t, BUFFER_SIZE> buf{};
  struct sockaddr_ll sender {};
  socklen_t sender_len = sizeof(sender);

  while (g_running) {
    ssize_t n =
        recvfrom(sock, buf.data(), BUFFER_SIZE, 0,
                 reinterpret_cast<struct sockaddr*>(&sender), &sender_len);
    if (n < 0) {
      if (g_running) perror("recvfrom");
      break;
    }

    EthernetFrame frame{};
    if (parse_ethernet_frame(buf.data(), static_cast<size_t>(n), frame))
      print_frame(frame, n);
  }

  close(sock);
  std::cout << "\nCaptured " << g_frame_count << " frame(s). Goodbye.\n";
  return 0;
}
