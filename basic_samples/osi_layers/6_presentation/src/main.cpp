#include <charconv>
#include <cstdint>
#include <format>
#include <iostream>
#include <span>
#include <string_view>
#include <system_error>

#include "compression.h"
#include "encoding.h"
#include "listener.h"
#include "ssl_info.h"
#include "tls_info.h"

namespace {

void print_usage(std::string_view prog) {
  std::cout << std::format(
      "Usage: {} [options]\n"
      "  (no args)        Run all presentation-layer demonstrations.\n"
      "  --listen [PORT]  Run a TLS listener on 127.0.0.1:PORT (default 4443)\n"
      "                   that accepts one client and reports presentation-\n"
      "                   layer info on the first received record.\n"
      "  -h, --help       Show this help.\n",
      prog);
}

[[nodiscard]] bool parse_port(std::string_view s, std::uint16_t& out) {
  unsigned value{};
  const auto* first = s.data();
  const auto* last = s.data() + s.size();
  auto [ptr, ec] = std::from_chars(first, last, value);
  if (ec != std::errc{} || ptr != last || value == 0 || value > 0xFFFFu) {
    return false;
  }
  out = static_cast<std::uint16_t>(value);
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  const std::span<char*> args{argv, static_cast<std::size_t>(argc)};
  const std::string_view prog =
      args.empty() ? "presentation_layer_demo" : std::string_view{args[0]};

  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string_view a{args[i]};
    if (a == "-h" || a == "--help") {
      print_usage(prog);
      return 0;
    }
    if (a == "--listen") {
      std::uint16_t port = 4443;
      if (i + 1 < args.size() && args[i + 1][0] != '-') {
        if (!parse_port(args[++i], port)) {
          std::cerr << "Invalid port.\n";
          return 2;
        }
      }
      return presentation::run_listener(port);
    }
    std::cerr << std::format("Unknown argument: {}\n", a);
    print_usage(prog);
    return 2;
  }

  std::cout << "############################################\n"
               "#  OSI Layer 6 - Presentation Layer Demo  #\n"
               "############################################\n\n"
               "The Presentation Layer translates between the application\n"
               "and network formats: character encoding, data compression,\n"
               "and encryption (SSL/TLS).\n\n";

  presentation::demonstrate_encoding();
  presentation::demonstrate_compression();
  presentation::demonstrate_tls();
  presentation::demonstrate_ssl();

  std::cout << "Tip: run with --listen [port] to start a TLS listener.\n";
  return 0;
}
