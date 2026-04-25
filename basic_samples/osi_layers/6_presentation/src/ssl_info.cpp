#include "ssl_info.h"

#include <openssl/ssl.h>

#include <array>
#include <format>
#include <iostream>
#include <string_view>

namespace presentation {

namespace {

enum class Status { Unavailable, Deprecated, Supported };

[[nodiscard]] constexpr std::string_view to_string(Status s) noexcept {
  switch (s) {
    case Status::Unavailable:
      return "unavailable";
    case Status::Deprecated:
      return "deprecated";
    case Status::Supported:
      return "supported";
  }
  return "?";
}

struct ProtoInfo {
  std::string_view name;
  Status status;
  std::string_view note;
};

}  // namespace

void demonstrate_ssl() {
  std::cout << "=== SSL (legacy Secure Sockets Layer) ===\n";
  std::cout
      << "Note: SSL 2.0 / 3.0 are obsolete and insecure (POODLE, DROWN).\n"
      << "      Modern OpenSSL builds disable them; TLS supersedes SSL.\n";

  constexpr std::array protos = {
      ProtoInfo{"SSL 2.0", Status::Unavailable, "removed; broken cryptography"},
      ProtoInfo{"SSL 3.0", Status::Unavailable,
                "removed; vulnerable to POODLE"},
      ProtoInfo{"TLS 1.0", Status::Deprecated, "deprecated by RFC 8996"},
      ProtoInfo{"TLS 1.1", Status::Deprecated, "deprecated by RFC 8996"},
      ProtoInfo{"TLS 1.2", Status::Supported, "widely supported"},
#ifdef TLS1_3_VERSION
      ProtoInfo{"TLS 1.3", Status::Supported,
                "current best practice (RFC 8446)"},
#endif
  };

  std::cout << "\nProtocol     Status        Notes\n";
  std::cout << "-----------  ------------  -----------------------------\n";
  for (const auto& p : protos) {
    std::cout << std::format("  {}    {:<12}  {}\n", p.name,
                             to_string(p.status), p.note);
  }
  std::cout << '\n';
}

}  // namespace presentation
