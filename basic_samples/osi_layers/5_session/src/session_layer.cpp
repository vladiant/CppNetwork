#include "session_layer.hpp"

#include <iostream>
#include <string_view>

namespace osi::session {

namespace {

using namespace std::string_view_literals;

constexpr auto kSep =
    "------------------------------------------------------------"sv;
constexpr auto kDouble =
    "============================================================"sv;

}  // namespace

std::vector<ProtocolInfo> getProtocols() {
  using P = Protocol;
  return {
      {.id = P::NetBIOS,
       .name = "NetBIOS",
       .fullName = "Network Basic Input/Output System",
       .transport = "TCP/UDP",
       .ports = "137 (NS), 138 (DGM), 139 (SSN)",
       .description =
           "Provides name, datagram and session services for legacy LAN apps.",
       .detailed = true},
      {.id = P::RPC,
       .name = "RPC",
       .fullName = "Remote Procedure Call (ONC/DCE/MS-RPC)",
       .transport = "TCP/UDP",
       .ports = "111 (portmapper), 135 (epmap), dynamic high ports",
       .description = "Lets a program invoke a procedure in another address "
                      "space as if local.",
       .detailed = true},
      {.id = P::SOCKS,
       .name = "SOCKS",
       .fullName = "Socket Secure Proxy Protocol",
       .transport = "TCP (UDP for SOCKS5 ASSOCIATE)",
       .ports = "1080",
       .description = "Session-layer proxy that relays TCP/UDP traffic on "
                      "behalf of clients.",
       .detailed = true},
      {.id = P::PPTP,
       .name = "PPTP",
       .fullName = "Point-to-Point Tunneling Protocol",
       .transport = "TCP + GRE",
       .ports = "1723 (control), IP proto 47 (data)",
       .description = "Legacy VPN tunneling protocol; control channel manages "
                      "PPP sessions.",
       .detailed = false},
      {.id = P::L2TP,
       .name = "L2TP",
       .fullName = "Layer 2 Tunneling Protocol",
       .transport = "UDP",
       .ports = "1701",
       .description =
           "Tunnels link-layer frames; commonly paired with IPsec for VPNs.",
       .detailed = false},
      {.id = P::SMB,
       .name = "SMB",
       .fullName = "Server Message Block",
       .transport = "TCP",
       .ports = "445 (direct), 139 (over NetBIOS)",
       .description =
           "File/printer sharing; manages user sessions and tree connects.",
       .detailed = false},
      {.id = P::SDP,
       .name = "SDP",
       .fullName = "Session Description Protocol",
       .transport = "Carried by SIP/RTSP",
       .ports = "n/a (payload format)",
       .description =
           "Describes multimedia session parameters for negotiation.",
       .detailed = false},
      {.id = P::ASP,
       .name = "ASP",
       .fullName = "AppleTalk Session Protocol",
       .transport = "ATP/DDP",
       .ports = "n/a (AppleTalk)",
       .description =
           "Opened/closed sessions between AppleTalk clients and servers.",
       .detailed = false},
      {.id = P::H245,
       .name = "H.245",
       .fullName = "ITU-T H.245 Control Protocol",
       .transport = "TCP",
       .ports = "dynamic",
       .description =
           "Controls multimedia communication sessions in H.323 stacks.",
       .detailed = false},
      {.id = P::ISO8327,
       .name = "ISO 8327 / X.225",
       .fullName = "OSI Connection-Oriented Session Protocol",
       .transport = "TPKT/TP0-TP4",
       .ports = "n/a (OSI stack)",
       .description =
           "Reference OSI session layer: tokens, dialog units, sync points.",
       .detailed = false},
  };
}

std::vector<SessionPhase> getSessionEstablishmentPhases() {
  return {
      {.name = "1. Connection Request",
       .description =
           "Initiator sends a CONNECT (CN) SPDU to the responder with proposed "
           "session parameters (tokens, version, requirements)."},
      {.name = "2. Parameter Negotiation",
       .description =
           "Peers negotiate functional units: half/full duplex, "
           "synchronization, activity management, and token assignment."},
      {.name = "3. Connection Confirmation",
       .description =
           "Responder replies with ACCEPT (AC) SPDU; the session connection "
           "endpoint is now established."},
      {.name = "4. Data Transfer / Dialog Control",
       .description = "Peers exchange Data SPDUs. Tokens (data, release, "
                      "synchronize-minor/major) regulate who may send."},
      {.name = "5. Synchronization & Checkpointing",
       .description =
           "Sync points (minor/major) are inserted so the dialog can be "
           "resynchronized or rolled back after errors."},
      {.name = "6. Activity Management",
       .description =
           "Long dialogs are split into activities that can be started, "
           "interrupted, resumed, discarded, or ended independently."},
      {.name = "7. Orderly Release",
       .description =
           "An endpoint that holds the release token issues FINISH (FN); "
           "peer responds with DISCONNECT (DN). Pending data is delivered."},
      {.name = "8. Abort (if needed)",
       .description =
           "Either side may issue ABORT (AB) SPDU to tear down the session "
           "immediately, discarding undelivered data."},
  };
}

void printProtocol(const ProtocolInfo& p) {
  std::cout << kSep << '\n'
            << "Protocol : " << p.name << " (" << p.fullName << ")\n"
            << "Transport: " << p.transport << '\n'
            << "Ports    : " << p.ports << '\n'
            << "Summary  : " << p.description << '\n';
}

void printDetailedNetBIOS() {
  std::cout << kDouble << '\n'
            << "NetBIOS - Network Basic Input/Output System\n"
            << kDouble << '\n';
  std::cout
      << "NetBIOS is an API and a session-layer protocol family that\n"
         "provides three independent services. On modern networks it\n"
         "runs over TCP/IP as NBT (NetBIOS over TCP/IP, RFC 1001/1002).\n\n"
         "Services:\n"
         "  * Name Service (NBNS) - UDP/137\n"
         "      Registers and resolves 16-byte NetBIOS names. WINS is\n"
         "      the Microsoft NBNS implementation.\n"
         "  * Datagram Service     - UDP/138\n"
         "      Connectionless one-to-many delivery (broadcasts,\n"
         "      browser announcements).\n"
         "  * Session Service      - TCP/139\n"
         "      Reliable, connection-oriented byte stream between two\n"
         "      named endpoints. Classic carrier for SMB v1.\n\n"
         "Session establishment over NBT (TCP/139):\n"
         "  1. TCP three-way handshake to port 139.\n"
         "  2. Client sends SESSION REQUEST PDU containing the called\n"
         "     and calling NetBIOS names (encoded, 34 bytes each).\n"
         "  3. Server replies POSITIVE SESSION RESPONSE (success) or\n"
         "     NEGATIVE SESSION RESPONSE (with error code).\n"
         "  4. SESSION MESSAGE PDUs carry upper-layer payload (e.g. SMB).\n"
         "  5. KEEP ALIVE PDUs may be exchanged.\n"
         "  6. TCP FIN tears the session down.\n";
}

void printDetailedRPC() {
  std::cout << kDouble << '\n'
            << "RPC - Remote Procedure Call\n"
            << kDouble << '\n';
  std::cout
      << "RPC lets a client invoke a procedure on a remote server using\n"
         "the same call/return semantics as a local function. The session\n"
         "layer role is to bind the caller to a remote endpoint, manage\n"
         "the call's lifetime, and (optionally) preserve context across\n"
         "calls.\n\n"
         "Common variants:\n"
         "  * ONC RPC / Sun RPC (RFC 5531) - uses portmapper on TCP/UDP 111.\n"
         "  * DCE/RPC (Open Group) - basis for Microsoft RPC; endpoint\n"
         "    mapper on TCP/UDP 135.\n"
         "  * gRPC - modern HTTP/2-based RPC (not session-layer in OSI\n"
         "    sense, but conceptually equivalent).\n\n"
         "Session establishment (ONC RPC example):\n"
         "  1. Client queries portmapper (port 111) with program number\n"
         "     and version, receives the dynamic port of the service.\n"
         "  2. Client opens TCP/UDP connection to that port.\n"
         "  3. Client sends a CALL message: xid, prog, vers, proc,\n"
         "     credentials, verifier, arguments (XDR-encoded).\n"
         "  4. Server replies with a REPLY message: same xid,\n"
         "     accepted/denied status, and results.\n"
         "  5. Multiple calls may be multiplexed by xid on one connection.\n"
         "  6. Connection close (or timeout) ends the session.\n\n"
         "DCE/RPC adds an explicit BIND/BIND_ACK handshake that\n"
         "negotiates an abstract syntax (interface UUID + version) and\n"
         "transfer syntax (NDR) before any call is made.\n";
}

void printDetailedSOCKS() {
  std::cout << kDouble << '\n'
            << "SOCKS - Socket Secure Proxy\n"
            << kDouble << '\n';
  std::cout
      << "SOCKS is a session-layer proxy that relays TCP (and, in v5,\n"
         "UDP) connections through an intermediary. It is application-\n"
         "agnostic: anything TCP-based can tunnel through it.\n\n"
         "Versions:\n"
         "  * SOCKS4  - IPv4 only, no auth, single CONNECT command.\n"
         "  * SOCKS4a - adds remote DNS resolution.\n"
         "  * SOCKS5  - RFC 1928: IPv4/IPv6/domain, auth methods,\n"
         "    CONNECT / BIND / UDP ASSOCIATE commands.\n\n"
         "SOCKS5 session establishment (default port 1080):\n"
         "  1. Client opens TCP to the SOCKS server.\n"
         "  2. Greeting:\n"
         "       Client -> [VER=0x05][NMETHODS][METHODS...]\n"
         "       Server -> [VER=0x05][METHOD]   (0x00 no-auth,\n"
         "                                       0x02 user/pass,\n"
         "                                       0xFF no acceptable)\n"
         "  3. Optional sub-negotiation per chosen method\n"
         "     (e.g. RFC 1929 username/password).\n"
         "  4. Request:\n"
         "       Client -> [VER][CMD][RSV=0x00][ATYP][DST.ADDR][DST.PORT]\n"
         "         CMD: 0x01 CONNECT, 0x02 BIND, 0x03 UDP ASSOCIATE\n"
         "         ATYP: 0x01 IPv4, 0x03 domain, 0x04 IPv6\n"
         "  5. Reply:\n"
         "       Server -> [VER][REP][RSV][ATYP][BND.ADDR][BND.PORT]\n"
         "         REP=0x00 success; non-zero = failure code.\n"
         "  6. After success, the TCP stream becomes a transparent\n"
         "     tunnel between client and the requested target.\n"
         "  7. Either side closes TCP to end the session.\n";
}

void printSessionEstablishment() {
  std::cout << kDouble << '\n'
            << "OSI Session Establishment (ITU-T X.225 / ISO 8327)\n"
            << kDouble << '\n';
  std::cout << "The OSI session layer (Layer 5) organizes and synchronizes\n"
               "the dialog between two presentation-layer entities. It does\n"
               "not move bytes itself; it controls *how* and *when* they are\n"
               "moved. The canonical service primitives are:\n\n"
               "    S-CONNECT, S-DATA, S-EXPEDITED-DATA, S-TOKEN-GIVE,\n"
               "    S-TOKEN-PLEASE, S-SYNC-MINOR, S-SYNC-MAJOR, S-RESYNC,\n"
               "    S-ACTIVITY-START/END/INTERRUPT/RESUME/DISCARD,\n"
               "    S-RELEASE, S-U-ABORT, S-P-ABORT.\n\n";
  for (const auto& [name, description] : getSessionEstablishmentPhases()) {
    std::cout << name << '\n' << "    " << description << "\n\n";
  }
}

void printOverview() {
  std::cout << kDouble << '\n'
            << "OSI LAYER 5 - SESSION LAYER\n"
            << kDouble << '\n';
  std::cout << "Role: Establish, manage, synchronize, and tear down dialogs\n"
               "      (sessions) between two endpoints. Provides:\n"
               "        - Dialog control (full / half duplex via tokens)\n"
               "        - Session checkpointing & resynchronization\n"
               "        - Activity management for long-running exchanges\n"
               "        - Graceful (orderly) and abrupt (abort) release\n"
               "Position: Above Transport (L4), below Presentation (L6).\n";
}

}  // namespace osi::session
