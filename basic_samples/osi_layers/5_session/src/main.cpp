#include <array>
#include <functional>
#include <iostream>
#include <span>
#include <string_view>

#include "listener.hpp"
#include "session_layer.hpp"

namespace {

using namespace std::string_view_literals;
using Action = std::function<int()>;

void printUsage(std::string_view prog) {
  std::cout << "Usage: " << prog << " [option]\n\n"
            << "Information modes:\n"
            << "  (no args)        Show full report (default)\n"
            << "  --overview       OSI Session layer role and position\n"
            << "  --establishment  Session establishment phases\n"
            << "  --netbios        Detailed NetBIOS information\n"
            << "  --rpc            Detailed RPC information\n"
            << "  --socks          Detailed SOCKS information\n"
            << "  --list           List all session-layer protocols (brief)\n"
            << "\nLive listener mode:\n"
            << "  --listen         Bind to known session-layer ports and\n"
            << "                   parse/print incoming traffic until Ctrl+C.\n"
            << "                   (Privileged ports <1024 need root or\n"
            << "                    cap_net_bind_service.)\n"
            << "  --ports          Show the ports --listen tries to bind\n"
            << "\n  --help, -h     Show this help message\n";
}

int runFull() {
  using namespace osi::session;
  printOverview();
  std::cout << '\n';
  printSessionEstablishment();
  std::cout << '\n';
  printDetailedNetBIOS();
  std::cout << '\n';
  printDetailedRPC();
  std::cout << '\n';
  printDetailedSOCKS();
  std::cout << "\nOther session-layer / session-oriented protocols:\n";
  for (const auto& p : getProtocols()) {
    if (!p.detailed) printProtocol(p);
  }
  return 0;
}

int printPorts() {
  using namespace osi::session;
  std::cout << "Ports the listener will try to bind:\n";
  for (const auto& p : defaultPorts()) {
    std::cout << "  " << toString(p.transport) << '/' << p.port << '\t'
              << p.protocol << "\t- " << p.note
              << (p.detailed ? "  [parsed]" : "  [logged only]") << '\n';
  }
  return 0;
}

int listAll() {
  for (const auto& p : osi::session::getProtocols()) {
    osi::session::printProtocol(p);
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace osi::session;
  const std::span<char*> args{argv, static_cast<std::size_t>(argc)};
  const std::string_view prog = (argc > 0) ? args[0] : "session_layer";

  if (argc < 2) return runFull();

  const std::string_view arg = args[1];

  struct Command {
    std::string_view flag;
    Action run;
  };
  const std::array<Command, 9> commands{{
      {"--overview"sv,
       [] {
         printOverview();
         return 0;
       }},
      {"--establishment"sv,
       [] {
         printSessionEstablishment();
         return 0;
       }},
      {"--netbios"sv,
       [] {
         printDetailedNetBIOS();
         return 0;
       }},
      {"--rpc"sv,
       [] {
         printDetailedRPC();
         return 0;
       }},
      {"--socks"sv,
       [] {
         printDetailedSOCKS();
         return 0;
       }},
      {"--list"sv, listAll},
      {"--ports"sv, printPorts},
      {"--listen"sv, [] { return runListener(defaultPorts()); }},
      {"--help"sv,
       [&] {
         printUsage(prog);
         return 0;
       }},
  }};

  if (arg == "-h"sv) {
    printUsage(prog);
    return 0;
  }
  for (const auto& cmd : commands) {
    if (cmd.flag == arg) return cmd.run();
  }

  std::cerr << "Unknown option: " << arg << "\n\n";
  printUsage(prog);
  return 1;
}
