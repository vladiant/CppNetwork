#include "listener.hpp"

#include <arpa/inet.h>
#include <arpa/nameser.h>  // QR/opcode constants for NBNS (shared with DNS)
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace osi::session {

namespace {

using namespace std::string_view_literals;
using ByteSpan = std::span<const std::uint8_t>;

// ---------- protocol constants ----------
// Linux/POSIX does not ship headers for these application-layer
// protocols, so we name the on-the-wire codes here per their RFCs.

// SOCKS (RFC 1928 / RFC 1929)
enum class SocksVersion : std::uint8_t {
  V4 = 0x04,
  V5 = 0x05,
};
enum class SocksAuthMethod : std::uint8_t {
  NoAuth = 0x00,
  GssApi = 0x01,
  UserPass = 0x02,
};
enum class SocksCommand : std::uint8_t {
  Connect = 0x01,
  Bind = 0x02,
  UdpAssociate = 0x03,
};

// NetBIOS Session Service PDU types (RFC 1002 §4.3.1)
enum class NbtType : std::uint8_t {
  SessionMessage = 0x00,
  SessionRequest = 0x81,
  PositiveSessionResponse = 0x82,
  NegativeSessionResponse = 0x83,
  RetargetSessionResponse = 0x84,
  KeepAlive = 0x85,
};

// DCE/RPC PDU types (DCE 1.1 §12.6 "Connection-oriented PDU types")
enum class DceRpcPType : std::uint8_t {
  Request = 0x00,
  Response = 0x02,
  Fault = 0x03,
  Bind = 0x0B,
  BindAck = 0x0C,
  BindNak = 0x0D,
  AlterContext = 0x0E,
  AlterContextResp = 0x0F,
  Auth3 = 0x11,
  CoCancel = 0x14,
};

// SMB magic bytes (MS-CIFS / MS-SMB2)
constexpr std::array<std::uint8_t, 4> kSmb1Magic{0xFF, 'S', 'M', 'B'};
constexpr std::array<std::uint8_t, 4> kSmb2Magic{0xFE, 'S', 'M', 'B'};
constexpr std::size_t kNbtHeaderSize = 4;

volatile std::sig_atomic_t g_stop = 0;

extern "C" void handleSignal(int) noexcept { g_stop = 1; }

// ---------- RAII for file descriptors ----------

class FileDescriptor {
 public:
  FileDescriptor() noexcept = default;
  explicit FileDescriptor(int fd) noexcept : fd_{fd} {}

  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;

  FileDescriptor(FileDescriptor&& o) noexcept : fd_{std::exchange(o.fd_, -1)} {}

  FileDescriptor& operator=(FileDescriptor&& o) noexcept {
    if (this != &o) {
      reset();
      fd_ = std::exchange(o.fd_, -1);
    }
    return *this;
  }

  ~FileDescriptor() { reset(); }

  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
  explicit operator bool() const noexcept { return valid(); }

  void reset() noexcept {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

 private:
  int fd_{-1};
};

// ---------- helpers ----------

[[nodiscard]] std::string nowStamp() {
  using namespace std::chrono;
  const auto t = system_clock::to_time_t(system_clock::now());
  std::tm tm{};
  ::localtime_r(&t, &tm);
  std::array<char, 16> buf{};
  std::strftime(buf.data(), buf.size(), "%H:%M:%S", &tm);
  return std::string{buf.data()};
}

[[nodiscard]] std::string peerString(const sockaddr_in& a) {
  std::array<char, INET_ADDRSTRLEN> ip{};
  ::inet_ntop(AF_INET, &a.sin_addr, ip.data(), ip.size());
  std::ostringstream os;
  os << ip.data() << ':' << ntohs(a.sin_port);
  return std::move(os).str();
}

[[nodiscard]] std::string hexPreview(ByteSpan data, std::size_t max = 24) {
  std::ostringstream os;
  os << std::hex << std::setfill('0');
  const auto k = std::min(data.size(), max);
  for (std::size_t i = 0; i < k; ++i) {
    os << std::setw(2) << static_cast<int>(data[i]);
    if (i + 1 < k) os << ' ';
  }
  if (data.size() > max) os << " ...";
  return std::move(os).str();
}

[[nodiscard]] std::string decodeNetbiosName(ByteSpan encoded) {
  std::string out;
  const auto n = std::min<std::size_t>(encoded.size() / 2, 16);
  out.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    const int hi = encoded[i * 2] - 'A';
    const int lo = encoded[i * 2 + 1] - 'A';
    const auto c = static_cast<char>((hi << 4) | lo);
    if (c == ' ' || c == '\0') break;
    out.push_back(c);
  }
  return out;
}

// ---------- protocol-specific parsers ----------

[[nodiscard]] std::string parseSocks(ByteSpan d) {
  if (d.size() < 2) return "(too short)";
  std::ostringstream os;
  const auto version = static_cast<SocksVersion>(d[0]);
  if (version == SocksVersion::V5) {
    const auto nmethods = d[1];
    os << "SOCKS5 greeting: nmethods=" << static_cast<int>(nmethods)
       << " methods=[";
    for (std::size_t i = 0; i < nmethods && 2 + i < d.size(); ++i) {
      if (i) os << ',';
      switch (static_cast<SocksAuthMethod>(d[2 + i])) {
        case SocksAuthMethod::NoAuth:
          os << "NO-AUTH";
          break;
        case SocksAuthMethod::GssApi:
          os << "GSSAPI";
          break;
        case SocksAuthMethod::UserPass:
          os << "USER/PASS";
          break;
        default:
          os << "0x" << std::hex << static_cast<int>(d[2 + i]) << std::dec;
      }
    }
    os << ']';
  } else if (version == SocksVersion::V4) {
    const auto cmd = static_cast<SocksCommand>(d[1]);
    os << "SOCKS4 request: cmd="
       << (cmd == SocksCommand::Connect ? "CONNECT"sv
           : cmd == SocksCommand::Bind  ? "BIND"sv
                                        : "?"sv);
    if (d.size() >= 8) {
      const std::uint16_t port = (d[2] << 8) | d[3];
      os << " port=" << port << " ip=" << static_cast<int>(d[4]) << '.'
         << static_cast<int>(d[5]) << '.' << static_cast<int>(d[6]) << '.'
         << static_cast<int>(d[7]);
    }
  } else {
    os << "non-SOCKS bytes: " << hexPreview(d);
  }
  return std::move(os).str();
}

[[nodiscard]] std::string parseNbtSession(ByteSpan d) {
  if (d.size() < kNbtHeaderSize) return "(too short)";
  constexpr auto typeName = [](NbtType t) -> std::string_view {
    switch (t) {
      case NbtType::SessionMessage:
        return "SESSION MESSAGE";
      case NbtType::SessionRequest:
        return "SESSION REQUEST";
      case NbtType::PositiveSessionResponse:
        return "POSITIVE SESSION RESPONSE";
      case NbtType::NegativeSessionResponse:
        return "NEGATIVE SESSION RESPONSE";
      case NbtType::RetargetSessionResponse:
        return "RETARGET SESSION RESPONSE";
      case NbtType::KeepAlive:
        return "KEEP ALIVE";
    }
    return "UNKNOWN";
  };
  // RFC 1002 §4.3.1: 24-bit length, high bit in flags byte (E).
  const std::uint32_t len = ((d[1] & 0x01u) << 16) | (d[2] << 8) | d[3];
  const auto type = static_cast<NbtType>(d[0]);
  std::ostringstream os;
  os << "NBT type=" << typeName(type) << " len=" << len;
  if (type == NbtType::SessionRequest && d.size() >= kNbtHeaderSize + 34) {
    os << " called=\"" << decodeNetbiosName(d.subspan(5, 32)) << '"';
  }
  return std::move(os).str();
}

[[nodiscard]] std::string parseNbns(ByteSpan d) {
  // NBNS reuses the DNS header layout (RFC 1002 §4.2.1.1).
  // <arpa/nameser.h> gives us NS_HFIXEDSZ (12-byte header) and the QR bit.
  if (d.size() < NS_HFIXEDSZ) return "(too short)";
  const std::uint16_t flags = (d[2] << 8) | d[3];
  constexpr std::uint16_t kQrBit = 1u << 15;  // matches ns_f_qr position
  std::ostringstream os;
  os << "NBNS " << ((flags & kQrBit) ? "response" : "query") << " txid=0x"
     << std::hex << ((d[0] << 8) | d[1]) << std::dec;
  if (d.size() >= NS_HFIXEDSZ + 1 + 32) {
    // 12-byte header + 1 length-octet (0x20) + 32-byte encoded name
    os << " name=\"" << decodeNetbiosName(d.subspan(NS_HFIXEDSZ + 1, 32))
       << '"';
  }
  return std::move(os).str();
}

[[nodiscard]] std::string parseDceRpc(ByteSpan d) {
  if (d.size() < 16) return "(too short)";
  constexpr auto ptypeName = [](DceRpcPType pt) -> std::string_view {
    switch (pt) {
      case DceRpcPType::Request:
        return "REQUEST";
      case DceRpcPType::Response:
        return "RESPONSE";
      case DceRpcPType::Fault:
        return "FAULT";
      case DceRpcPType::Bind:
        return "BIND";
      case DceRpcPType::BindAck:
        return "BIND_ACK";
      case DceRpcPType::BindNak:
        return "BIND_NAK";
      case DceRpcPType::AlterContext:
        return "ALTER_CONTEXT";
      case DceRpcPType::AlterContextResp:
        return "ALTER_CONTEXT_RESP";
      case DceRpcPType::Auth3:
        return "AUTH3";
      case DceRpcPType::CoCancel:
        return "CO_CANCEL";
    }
    return "?";
  };
  std::ostringstream os;
  os << "DCE/RPC v" << static_cast<int>(d[0]) << '.' << static_cast<int>(d[1])
     << " ptype=" << ptypeName(static_cast<DceRpcPType>(d[2]));
  return std::move(os).str();
}

[[nodiscard]] std::string parseSmb(ByteSpan d) {
  constexpr auto starts = [](ByteSpan s, std::size_t off,
                             std::array<std::uint8_t, 4> magic) {
    if (s.size() < off + magic.size()) return false;
    return std::equal(magic.begin(), magic.end(), s.begin() + off);
  };
  if (starts(d, 0, kSmb1Magic)) return "SMB1 header";
  if (starts(d, 0, kSmb2Magic)) return "SMB2/3 header";
  if (starts(d, kNbtHeaderSize, kSmb1Magic)) return "NBT-wrapped SMB1";
  if (starts(d, kNbtHeaderSize, kSmb2Magic)) return "NBT-wrapped SMB2/3";
  return "non-SMB bytes: " + hexPreview(d);
}

[[nodiscard]] std::string parsePayload(std::string_view proto, ByteSpan d) {
  if (proto == "SOCKS"sv) return parseSocks(d);
  if (proto == "NetBIOS-SSN"sv) return parseNbtSession(d);
  if (proto == "NetBIOS-NS"sv) return parseNbns(d);
  if (proto == "NetBIOS-DGM"sv) return "NetBIOS datagram, " + hexPreview(d);
  if (proto == "MS-RPC"sv || proto == "Sun-RPC-portmap"sv)
    return parseDceRpc(d);
  if (proto == "SMB"sv) return parseSmb(d);
  return hexPreview(d);
}

// ---------- socket creation ----------

struct BindResult {
  FileDescriptor fd;
  std::error_code error;
};

[[nodiscard]] BindResult bindSocket(Transport t, std::uint16_t port) {
  const int type = (t == Transport::Tcp) ? SOCK_STREAM : SOCK_DGRAM;
  FileDescriptor fd{::socket(AF_INET, type, 0)};
  if (!fd) return {{}, std::error_code{errno, std::system_category()}};

  constexpr int yes = 1;
  ::setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    return {{}, std::error_code{errno, std::system_category()}};
  }
  if (t == Transport::Tcp && ::listen(fd.get(), 16) < 0) {
    return {{}, std::error_code{errno, std::system_category()}};
  }
  return {std::move(fd), {}};
}

// ---------- per-connection state ----------

struct Listener {
  FileDescriptor fd;
  PortSpec spec;
  [[nodiscard]] bool isTcp() const noexcept {
    return spec.transport == Transport::Tcp;
  }
};

struct Client {
  FileDescriptor fd;
  std::string protocol;
  sockaddr_in peer{};
};

void installSignalHandlers() {
  std::signal(SIGINT, &handleSignal);
  std::signal(SIGTERM, &handleSignal);
  std::signal(SIGPIPE, SIG_IGN);
}

}  // namespace

std::vector<PortSpec> defaultPorts() {
  using T = Transport;
  return {
      {.protocol = "NetBIOS-NS",
       .transport = T::Udp,
       .port = 137,
       .note = "NetBIOS Name Service",
       .detailed = true},
      {.protocol = "NetBIOS-DGM",
       .transport = T::Udp,
       .port = 138,
       .note = "NetBIOS Datagram Service",
       .detailed = true},
      {.protocol = "NetBIOS-SSN",
       .transport = T::Tcp,
       .port = 139,
       .note = "NetBIOS Session Service",
       .detailed = true},
      {.protocol = "Sun-RPC-portmap",
       .transport = T::Tcp,
       .port = 111,
       .note = "ONC RPC portmapper",
       .detailed = true},
      {.protocol = "MS-RPC",
       .transport = T::Tcp,
       .port = 135,
       .note = "DCE/MS-RPC endpoint mapper",
       .detailed = true},
      {.protocol = "SOCKS",
       .transport = T::Tcp,
       .port = 1080,
       .note = "SOCKS proxy",
       .detailed = true},
      {.protocol = "SMB",
       .transport = T::Tcp,
       .port = 445,
       .note = "SMB direct (over TCP)",
       .detailed = true},
      {.protocol = "PPTP",
       .transport = T::Tcp,
       .port = 1723,
       .note = "PPTP control channel",
       .detailed = false},
      {.protocol = "L2TP",
       .transport = T::Udp,
       .port = 1701,
       .note = "L2TP control",
       .detailed = false},
      {.protocol = "H.323-Q.931",
       .transport = T::Tcp,
       .port = 1720,
       .note = "H.323 call signalling",
       .detailed = false},
  };
}

int runListener(const std::vector<PortSpec>& ports) {
  installSignalHandlers();

  std::vector<Listener> listeners;
  listeners.reserve(ports.size());

  std::cout << "Binding session-layer ports on 0.0.0.0...\n";
  for (const auto& spec : ports) {
    auto result = bindSocket(spec.transport, spec.port);
    if (!result.fd) {
      std::cerr << "  [skip] " << spec.protocol << '/'
                << toString(spec.transport) << ':' << spec.port << " - "
                << result.error.message() << '\n';
      continue;
    }
    std::cout << "  [ ok ] " << spec.protocol << '/' << toString(spec.transport)
              << ':' << spec.port << "  " << spec.note << '\n';
    listeners.push_back({.fd = std::move(result.fd), .spec = spec});
  }

  if (listeners.empty()) {
    std::cerr << "\nNo ports bound. On Linux, ports < 1024 require\n"
                 "CAP_NET_BIND_SERVICE or root. Try:\n"
                 "    sudo ./session_layer --listen\n"
                 "or grant the capability once with:\n"
                 "    sudo setcap 'cap_net_bind_service=+ep' "
                 "./build/session_layer\n";
    return 1;
  }

  std::cout << "\nListening. Press Ctrl+C to stop.\n"
            << std::string(60, '-') << '\n';

  std::vector<Client> clients;
  std::array<std::uint8_t, 4096> buf{};

  while (g_stop == 0) {
    std::vector<pollfd> pfds;
    pfds.reserve(listeners.size() + clients.size());
    for (const auto& l : listeners)
      pfds.push_back({.fd = l.fd.get(), .events = POLLIN, .revents = 0});
    for (const auto& c : clients)
      pfds.push_back({.fd = c.fd.get(), .events = POLLIN, .revents = 0});

    const int n = ::poll(pfds.data(), pfds.size(), 1000);
    if (n < 0) {
      if (errno == EINTR) continue;
      std::perror("poll");
      break;
    }
    if (n == 0) continue;

    // Listener events
    for (std::size_t i = 0; i < listeners.size(); ++i) {
      if ((pfds[i].revents & POLLIN) == 0) continue;
      auto& l = listeners[i];
      if (l.isTcp()) {
        sockaddr_in peer{};
        socklen_t pl = sizeof(peer);
        FileDescriptor c{
            ::accept(l.fd.get(), reinterpret_cast<sockaddr*>(&peer), &pl)};
        if (!c) {
          if (errno != EINTR) std::perror("accept");
          continue;
        }
        std::cout << '[' << nowStamp() << "] " << l.spec.protocol
                  << " TCP connect from " << peerString(peer) << " (port "
                  << l.spec.port << ")\n";
        clients.push_back(
            {.fd = std::move(c), .protocol = l.spec.protocol, .peer = peer});
      } else {
        sockaddr_in peer{};
        socklen_t pl = sizeof(peer);
        const ssize_t r = ::recvfrom(l.fd.get(), buf.data(), buf.size(), 0,
                                     reinterpret_cast<sockaddr*>(&peer), &pl);
        if (r <= 0) continue;
        const ByteSpan view{buf.data(), static_cast<std::size_t>(r)};
        std::cout << '[' << nowStamp() << "] " << l.spec.protocol
                  << " UDP datagram from " << peerString(peer) << " (" << r
                  << " bytes): " << parsePayload(l.spec.protocol, view) << '\n';
      }
    }

    // Client events
    const std::size_t base = listeners.size();
    for (std::size_t i = 0; i < clients.size();) {
      const short rev = pfds[base + i].revents;
      if (rev == 0) {
        ++i;
        continue;
      }
      const ssize_t r = ::recv(clients[i].fd.get(), buf.data(), buf.size(), 0);
      if (r <= 0) {
        std::cout << '[' << nowStamp() << "] " << clients[i].protocol
                  << " disconnect " << peerString(clients[i].peer) << '\n';
        clients.erase(clients.begin() + static_cast<std::ptrdiff_t>(i));
        continue;
      }
      const ByteSpan view{buf.data(), static_cast<std::size_t>(r)};
      std::cout << '[' << nowStamp() << "] " << clients[i].protocol << " from "
                << peerString(clients[i].peer) << " (" << r
                << " B): " << parsePayload(clients[i].protocol, view) << '\n';
      ++i;
    }
  }

  std::cout << "\nShutting down.\n";
  // RAII closes all sockets.
  return 0;
}

}  // namespace osi::session
