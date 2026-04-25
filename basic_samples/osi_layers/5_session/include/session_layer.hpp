#pragma once

#include <string>
#include <vector>

namespace osi::session {

enum class Protocol {
  NetBIOS,
  RPC,
  SOCKS,
  PPTP,
  L2TP,
  SMB,
  SDP,
  ASP,
  H245,
  ISO8327,
};

struct ProtocolInfo {
  Protocol id{};
  std::string name;
  std::string fullName;
  std::string transport;
  std::string ports;
  std::string description;
  bool detailed{false};
};

// Phases of session establishment (OSI session layer, ITU-T X.225 / ISO 8327).
struct SessionPhase {
  std::string name;
  std::string description;
};

[[nodiscard]] std::vector<ProtocolInfo> getProtocols();
[[nodiscard]] std::vector<SessionPhase> getSessionEstablishmentPhases();

void printProtocol(const ProtocolInfo& proto);
void printDetailedNetBIOS();
void printDetailedRPC();
void printDetailedSOCKS();
void printSessionEstablishment();
void printOverview();

}  // namespace osi::session
