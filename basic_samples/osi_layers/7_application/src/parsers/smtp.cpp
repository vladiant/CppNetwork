#include <cctype>
#include <cstring>
#include <sstream>
#include <string_view>

#include "../packet.hpp"

namespace appsniff {

namespace {

bool is_smtp_port(std::uint16_t p) {
  return p == 25 || p == 587 || p == 465 || p == 2525;
}

bool starts_with_ci(std::string_view s, std::string_view p) {
  if (s.size() < p.size()) return false;
  for (std::size_t i = 0; i < p.size(); ++i) {
    const auto a = std::toupper(static_cast<unsigned char>(s[i]));
    const auto b = std::toupper(static_cast<unsigned char>(p[i]));
    if (a != b) return false;
  }
  return true;
}

bool is_smtp_command(std::string_view sv) {
  static constexpr std::string_view cmds[] = {
      "HELO ", "EHLO ", "MAIL ", "RCPT ", "DATA",  "RSET",    "NOOP",
      "QUIT",  "VRFY ", "EXPN ", "HELP",  "AUTH ", "STARTTLS"};
  for (auto c : cmds) {
    if (starts_with_ci(sv, c)) return true;
    if (c.back() != ' ' && sv.size() >= c.size() && starts_with_ci(sv, c) &&
        (sv.size() == c.size() || sv[c.size()] == '\r' || sv[c.size()] == '\n'))
      return true;
  }
  return false;
}

bool is_smtp_response(std::string_view sv) {
  if (sv.size() < 4) return false;
  if (!std::isdigit(static_cast<unsigned char>(sv[0]))) return false;
  if (!std::isdigit(static_cast<unsigned char>(sv[1]))) return false;
  if (!std::isdigit(static_cast<unsigned char>(sv[2]))) return false;
  return sv[3] == ' ' || sv[3] == '-';
}

}  // namespace

bool try_parse_smtp(const PacketView& pkt) {
  if (pkt.proto != IpProto::Tcp) return false;
  if (!is_smtp_port(pkt.src_port) && !is_smtp_port(pkt.dst_port)) return false;
  if (pkt.payload.size() < 4) return false;

  std::string_view sv(reinterpret_cast<const char*>(pkt.payload.data()),
                      pkt.payload.size());

  const bool req = is_smtp_command(sv);
  const bool resp = !req && is_smtp_response(sv);
  if (!req && !resp) return false;

  auto eol = sv.find("\r\n");
  if (eol == std::string_view::npos)
    eol = std::min<std::size_t>(sv.size(), 200);
  std::string first(sv.substr(0, eol));

  std::ostringstream info;
  info << (req ? "C: " : "S: ") << first;
  log_line("SMTP", pkt, info.str());
  return true;
}

}  // namespace appsniff
