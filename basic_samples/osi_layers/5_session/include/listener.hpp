#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace osi::session {

enum class Transport { Tcp, Udp };

[[nodiscard]] constexpr std::string_view toString(Transport t) noexcept {
  return t == Transport::Tcp ? "tcp" : "udp";
}

struct PortSpec {
  std::string protocol;  // e.g. "NetBIOS-SSN"
  Transport transport{Transport::Tcp};
  std::uint16_t port{0};
  std::string note;      // brief description
  bool detailed{false};  // do we have a dedicated parser?
};

[[nodiscard]] std::vector<PortSpec> defaultPorts();

// Run a poll() loop binding to every port in `ports`.
// Sockets that cannot be bound (e.g. EACCES on privileged ports) are
// reported and skipped. Returns when SIGINT/SIGTERM is received.
// Returns 0 on success, non-zero if no socket could be bound at all.
int runListener(const std::vector<PortSpec>& ports);

}  // namespace osi::session
