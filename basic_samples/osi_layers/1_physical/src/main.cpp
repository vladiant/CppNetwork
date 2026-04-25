// OSI Layer 1 (Physical) reader for Linux.
//
// The OSI physical layer is concerned with the raw transmission of bits over
// a medium: cabling, signalling, link state, line rate, duplex, and the raw
// octet stream as it leaves/enters the NIC before any higher-layer framing
// is interpreted.
//
// On Linux, user space cannot touch the wire directly, but it can get as
// close as possible by:
//
//   1. Querying physical-link properties of an interface via the ethtool
//      ioctl interface (link up/down, speed in Mbit/s, duplex, MAC address,
//      MTU). These describe the physical channel.
//
//   2. Opening an AF_PACKET / SOCK_RAW socket bound to a single interface
//      with protocol ETH_P_ALL. The kernel then hands us the raw octet
//      stream that arrives on / leaves that NIC, exactly as it sits on the
//      wire (minus the preamble, SFD and FCS that the PHY/MAC strips). We
//      print those octets as hex AND as a bit string -- which is the
//      closest representation of "the bits on the wire" available to a
//      portable userspace program.
//
// Build:
//     cmake -S . -B build && cmake --build build
//
// Run (needs CAP_NET_RAW, easiest is sudo):
//     sudo ./build/osi_physical               # list interfaces + properties
//     sudo ./build/osi_physical <iface> [N]   # also capture N raw frames
//
// Example:
//     sudo ./build/osi_physical eth0 3

#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::string mac_to_string(const unsigned char* mac) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (int i = 0; i < 6; ++i) {
    if (i) oss << ':';
    oss << std::setw(2) << static_cast<int>(mac[i]);
  }
  return oss.str();
}

std::string duplex_to_string(uint8_t d) {
  switch (d) {
    case DUPLEX_HALF:
      return "half";
    case DUPLEX_FULL:
      return "full";
    default:
      return "unknown";
  }
}

// Run an ioctl on a freshly opened AF_INET datagram socket (the standard way
// to query interface properties on Linux).
int do_ifioctl(int request, ifreq& ifr) {
  int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return -1;
  int rc = ::ioctl(fd, request, &ifr);
  int saved = errno;
  ::close(fd);
  errno = saved;
  return rc;
}

struct PhyInfo {
  std::string name;
  std::string mac;
  int mtu = -1;
  bool link_up = false;
  bool link_known = false;
  int speed_mbps = -1;    // -1 if unknown / virtual
  uint8_t duplex = 0xff;  // 0xff if unknown
};

PhyInfo query_phy(const std::string& ifname) {
  PhyInfo info;
  info.name = ifname;

  ifreq ifr{};
  std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

  if (do_ifioctl(SIOCGIFHWADDR, ifr) == 0) {
    info.mac =
        mac_to_string(reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data));
  }

  std::memset(&ifr, 0, sizeof(ifr));
  std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
  if (do_ifioctl(SIOCGIFMTU, ifr) == 0) {
    info.mtu = ifr.ifr_mtu;
  }

  std::memset(&ifr, 0, sizeof(ifr));
  std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
  if (do_ifioctl(SIOCGIFFLAGS, ifr) == 0) {
    info.link_known = true;
    info.link_up = (ifr.ifr_flags & IFF_RUNNING) != 0;
  }

  // ETHTOOL_GSET gives speed/duplex for real Ethernet NICs. Will fail
  // with EOPNOTSUPP / EINVAL on loopback, tun, wifi-in-monitor, etc.
  ethtool_cmd ecmd{};
  ecmd.cmd = ETHTOOL_GSET;
  std::memset(&ifr, 0, sizeof(ifr));
  std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
  ifr.ifr_data = reinterpret_cast<char*>(&ecmd);
  if (do_ifioctl(SIOCETHTOOL, ifr) == 0) {
    info.speed_mbps = ethtool_cmd_speed(&ecmd);
    info.duplex = ecmd.duplex;
  }

  return info;
}

void print_phy(const PhyInfo& p) {
  std::cout << "  " << std::left << std::setw(16) << p.name
            << "  MAC=" << (p.mac.empty() ? "??:??:??:??:??:??" : p.mac);
  if (p.mtu >= 0) std::cout << "  MTU=" << p.mtu;
  if (p.link_known) std::cout << "  link=" << (p.link_up ? "UP" : "DOWN");
  if (p.speed_mbps > 0 && p.speed_mbps != static_cast<int>(SPEED_UNKNOWN))
    std::cout << "  speed=" << p.speed_mbps << "Mb/s";
  if (p.duplex != 0xff) std::cout << "  duplex=" << duplex_to_string(p.duplex);
  std::cout << '\n';
}

void list_interfaces() {
  int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    std::perror("socket");
    return;
  }

  ifconf ifc{};
  std::vector<char> buf(8192);
  ifc.ifc_len = static_cast<int>(buf.size());
  ifc.ifc_buf = buf.data();
  if (::ioctl(fd, SIOCGIFCONF, &ifc) < 0) {
    std::perror("SIOCGIFCONF");
    ::close(fd);
    return;
  }
  ::close(fd);

  std::cout << "Detected interfaces (Layer 1 view):\n";
  const ifreq* it = ifc.ifc_req;
  const int cnt = ifc.ifc_len / static_cast<int>(sizeof(ifreq));
  for (int i = 0; i < cnt; ++i) {
    print_phy(query_phy(it[i].ifr_name));
  }
}

std::string bytes_to_hex(const uint8_t* data, size_t n) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < n; ++i) {
    if (i && (i % 16) == 0)
      oss << '\n';
    else if (i)
      oss << ' ';
    oss << std::setw(2) << static_cast<int>(data[i]);
  }
  return oss.str();
}

std::string bytes_to_bits(const uint8_t* data, size_t n) {
  std::ostringstream oss;
  for (size_t i = 0; i < n; ++i) {
    if (i && (i % 8) == 0)
      oss << '\n';
    else if (i)
      oss << ' ';
    for (int b = 7; b >= 0; --b) {
      oss << ((data[i] >> b) & 1);
    }
  }
  return oss.str();
}

int capture_raw(const std::string& ifname, int count) {
  // AF_PACKET + SOCK_RAW + ETH_P_ALL = give me the raw octet stream
  // (link-layer frames) for every protocol on this NIC.
  int fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    std::perror("socket(AF_PACKET) -- need CAP_NET_RAW (try sudo)");
    return 1;
  }

  unsigned idx = ::if_nametoindex(ifname.c_str());
  if (idx == 0) {
    std::perror(("if_nametoindex(" + ifname + ")").c_str());
    ::close(fd);
    return 1;
  }

  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = static_cast<int>(idx);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
    std::perror("bind");
    ::close(fd);
    return 1;
  }

  std::cout << "\nCapturing " << count << " raw frame(s) on " << ifname
            << " (Ctrl-C to stop early)...\n";

  std::vector<uint8_t> frame(65536);
  for (int i = 0; i < count; ++i) {
    sockaddr_ll from{};
    socklen_t flen = sizeof(from);
    ssize_t n = ::recvfrom(fd, frame.data(), frame.size(), 0,
                           reinterpret_cast<sockaddr*>(&from), &flen);
    if (n < 0) {
      if (errno == EINTR) break;
      std::perror("recvfrom");
      ::close(fd);
      return 1;
    }

    const char* dir = (from.sll_pkttype == PACKET_OUTGOING) ? "TX" : "RX";
    std::cout << "\n--- frame #" << (i + 1) << " (" << dir << ", " << n
              << " bytes on the wire) ---\n";
    std::cout << "hex:\n"
              << bytes_to_hex(frame.data(), static_cast<size_t>(n)) << '\n';
    std::cout << "bits (MSB first per octet):\n"
              << bytes_to_bits(frame.data(), static_cast<size_t>(n)) << '\n';
  }

  ::close(fd);
  return 0;
}

void usage(const char* argv0) {
  std::cerr << "Usage:\n"
            << "  " << argv0
            << "                 list interfaces & physical properties\n"
            << "  " << argv0
            << " <iface> [N]     capture N raw frames (default 1)\n"
            << "\nNeeds CAP_NET_RAW for capture (run with sudo).\n";
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 1) {
    list_interfaces();
    return 0;
  }
  if (argc >= 2) {
    std::string_view a1 = argv[1];
    if (a1 == "-h" || a1 == "--help") {
      usage(argv[0]);
      return 0;
    }
    std::string ifname = std::string(a1);
    int count = (argc >= 3) ? std::atoi(argv[2]) : 1;
    if (count <= 0) count = 1;

    std::cout << "Physical-layer properties of " << ifname << ":\n";
    print_phy(query_phy(ifname));
    return capture_raw(ifname, count);
  }
  usage(argv[0]);
  return 1;
}
