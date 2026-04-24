// Transport-layer (OSI L4) sniffer — modern C++20 entry point.
//
// Opens an AF_PACKET / SOCK_RAW / ETH_P_ALL socket (the same mechanism used
// by tcpdump/libpcap), strips the link-layer header, and hands the IP
// packet to the decoders in transport_sniffer.{hpp,cpp}.
//
// Requires CAP_NET_RAW (run via sudo or `setcap cap_net_raw=eip ./binary`).

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <charconv>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "transport_sniffer.hpp"

namespace {

std::atomic<bool> g_run{true};

extern "C" void on_signal(int) noexcept {
  g_run.store(false, std::memory_order_relaxed);
}

// RAII wrapper for a POSIX file descriptor.
class FileDescriptor {
 public:
  FileDescriptor() noexcept = default;
  explicit FileDescriptor(int fd) noexcept : fd_{fd} {}

  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;

  FileDescriptor(FileDescriptor&& other) noexcept
      : fd_{std::exchange(other.fd_, -1)} {}

  FileDescriptor& operator=(FileDescriptor&& other) noexcept {
    if (this != &other) {
      reset();
      fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
  }

  ~FileDescriptor() { reset(); }

  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

  void reset() noexcept {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

 private:
  int fd_{-1};
};

struct CliOptions {
  std::string_view iface;
  long max_packets{0};
};

[[nodiscard]] std::optional<long> parse_long(std::string_view sv) noexcept {
  long v{};
  const auto* first = sv.data();
  const auto* last = sv.data() + sv.size();
  auto [p, ec] = std::from_chars(first, last, v);
  if (ec != std::errc{} || p != last) return std::nullopt;
  return v;
}

[[nodiscard]] std::optional<CliOptions> parse_args(std::span<char*> args) {
  CliOptions opts;
  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string_view a{args[i]};
    if (a == "-i" && i + 1 < args.size()) {
      opts.iface = args[++i];
    } else if (a == "-n" && i + 1 < args.size()) {
      if (auto v = parse_long(args[++i]))
        opts.max_packets = *v;
      else
        return std::nullopt;
    } else if (a == "-h" || a == "--help") {
      std::cout << "Usage: " << args[0] << " [-i <iface>] [-n <packet-count>]\n"
                << "  -i <iface>  Bind to a specific interface (e.g. eth0, lo, "
                   "wlan0)\n"
                << "  -n <N>      Exit after N packets (default: unlimited)\n";
      return std::nullopt;
    } else if (!a.empty() && a.front() != '-') {
      if (auto v = parse_long(a)) opts.max_packets = *v;
    } else {
      std::cerr << "Unknown argument: " << a << '\n';
      return std::nullopt;
    }
  }
  return opts;
}

[[nodiscard]] FileDescriptor open_packet_socket(std::string_view iface) {
  FileDescriptor fd{::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))};
  if (!fd.valid()) {
    std::perror("socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)");
    if (errno == EPERM) {
      std::cerr
          << "  Hint: AF_PACKET sockets require CAP_NET_RAW.\n"
             "        Try: sudo ./transport_sniffer\n"
             "        Or:  sudo setcap cap_net_raw=eip ./transport_sniffer\n";
    }
    return FileDescriptor{};
  }

  if (iface.empty()) return fd;

  // if_nametoindex wants a C string.
  std::string iface_cstr{iface};
  const unsigned idx = ::if_nametoindex(iface_cstr.c_str());
  if (idx == 0) {
    std::perror("if_nametoindex");
    return FileDescriptor{};
  }

  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = static_cast<int>(idx);

  if (::bind(fd.get(),
             reinterpret_cast<const sockaddr*>(
                 &sll),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
             sizeof(sll)) < 0) {
    std::perror("bind");
    return FileDescriptor{};
  }
  return fd;
}

// Strip the link-layer header for the frame and return the L3 payload
// together with the EtherType. Returns std::nullopt on truncated frames.
struct L3View {
  transport::byte_span bytes;
  std::uint16_t ethertype;
};

[[nodiscard]] std::optional<L3View> strip_linklayer(
    transport::byte_span frame, const sockaddr_ll& sll) noexcept {
  auto etype = static_cast<std::uint16_t>(ntohs(sll.sll_protocol));

  // ARPHRD_ETHER = 1, ARPHRD_LOOPBACK = 772 (also Ethernet-framed).
  if (sll.sll_hatype == 1 || sll.sll_hatype == 772) {
    if (frame.size() < ETH_HLEN) return std::nullopt;
    auto read_be16 = [&](std::size_t off) {
      return static_cast<std::uint16_t>(
          (static_cast<std::uint16_t>(frame[off]) << 8) | frame[off + 1]);
    };
    std::uint16_t e = read_be16(12);
    std::size_t off = ETH_HLEN;
    while (e == 0x8100U && off + 4 <= frame.size()) {  // 802.1Q VLAN
      e = read_be16(off + 2);
      off += 4;
    }
    return L3View{frame.subspan(off), e};
  }

  // Best-effort for tun/ppp/etc.: trust sll_protocol, assume no link header.
  return L3View{frame, etype};
}

}  // namespace

int main(int argc, char** argv) {
  const auto opts = parse_args({argv, static_cast<std::size_t>(argc)});
  if (!opts) return EXIT_FAILURE;

  std::cout << "OSI Layer 4 (Transport) sniffer\n"
               "================================\n"
               "Decodes: TCP, UDP, SCTP, QUIC (over UDP).\n"
               "Other L4 protocols are summarized.\n"
            << "Interface: " << (opts->iface.empty() ? "(all)" : opts->iface)
            << '\n'
            << "Press Ctrl+C to stop";
  if (opts->max_packets > 0)
    std::cout << " (or after " << opts->max_packets << " packets).";
  else
    std::cout << '.';
  std::cout << "\n\n";

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);

  FileDescriptor sock = open_packet_socket(opts->iface);
  if (!sock.valid()) return EXIT_FAILURE;

  std::vector<std::uint8_t> buf(65536);
  pollfd pfd{sock.get(), POLLIN, 0};

  long count = 0;
  while (g_run.load(std::memory_order_relaxed)) {
    const int r = ::poll(&pfd, 1, 500);
    if (r < 0) {
      if (errno == EINTR) continue;
      std::perror("poll");
      break;
    }
    if (r == 0 || (pfd.revents & POLLIN) == 0) continue;

    sockaddr_ll sll{};
    socklen_t slen = sizeof(sll);
    const ssize_t n = ::recvfrom(
        sock.get(), buf.data(), buf.size(), 0,
        reinterpret_cast<sockaddr*>(
            &sll),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        &slen);
    if (n <= 0) {
      if (n < 0 && errno != EINTR) std::perror("recvfrom");
      continue;
    }

    const transport::byte_span frame{buf.data(), static_cast<std::size_t>(n)};
    const auto l3 = strip_linklayer(frame, sll);
    if (!l3) continue;

    bool ok = false;
    switch (l3->ethertype) {
      case ETH_P_IP:
        ok = transport::decode_ipv4(l3->bytes);
        break;
      case ETH_P_IPV6:
        ok = transport::decode_ipv6(l3->bytes);
        break;
      default:
        continue;  // ARP, LLDP, STP, etc.
    }

    if (ok) {
      ++count;
      if (opts->max_packets > 0 && count >= opts->max_packets) break;
    }
  }

  std::cout << "\nCaptured " << count << " packets.\n";
  return EXIT_SUCCESS;
}
