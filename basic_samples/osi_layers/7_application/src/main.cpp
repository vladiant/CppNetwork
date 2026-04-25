#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include "sniffer.hpp"

namespace {
appsniff::Sniffer* g_sniffer = nullptr;

void on_signal(int) {
  if (g_sniffer) g_sniffer->stop();
}

void print_usage(const char* prog) {
  std::cerr
      << "Usage: " << prog
      << " [options]\n"
         "\n"
         "Options:\n"
         "  -i, --interface <name>   Network interface to capture on (default: "
         "auto)\n"
         "  -f, --filter   <expr>    Additional BPF filter expression\n"
         "  -s, --snaplen  <bytes>   Snapshot length (default: 65535)\n"
         "      --no-promisc         Disable promiscuous mode\n"
         "  -h, --help               Show this help\n"
         "\n"
         "Detected protocols: HTTP, HTTP/2, QUIC, DNS, TLS, SMTP, MQTT, RTP\n"
         "\n"
         "Note: requires CAP_NET_RAW (run with sudo or set capabilities on the "
         "binary):\n"
         "  sudo setcap cap_net_raw,cap_net_admin=eip ./app_layer_sniffer\n";
}

}  // namespace

int main(int argc, char** argv) {
  appsniff::SnifferOptions opts;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto need = [&](const char* name) -> const char* {
      if (i + 1 >= argc) {
        std::cerr << "error: " << name << " requires an argument\n";
        std::exit(2);
      }
      return argv[++i];
    };
    if (a == "-h" || a == "--help") {
      print_usage(argv[0]);
      return 0;
    } else if (a == "-i" || a == "--interface")
      opts.interface = need("--interface");
    else if (a == "-f" || a == "--filter")
      opts.bpf_filter = need("--filter");
    else if (a == "-s" || a == "--snaplen")
      opts.snaplen = std::atoi(need("--snaplen"));
    else if (a == "--no-promisc")
      opts.promiscuous = false;
    else {
      std::cerr << "error: unknown argument: " << a << "\n\n";
      print_usage(argv[0]);
      return 2;
    }
  }

  try {
    appsniff::Sniffer sniffer(std::move(opts));
    g_sniffer = &sniffer;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    sniffer.run();
  } catch (const std::exception& ex) {
    std::cerr << "fatal: " << ex.what() << '\n';
    return 1;
  }
  return 0;
}
