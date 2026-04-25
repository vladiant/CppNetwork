#include <array>
#include <cctype>
#include <cstring>
#include <sstream>
#include <string>
#include <string_view>

#include "../packet.hpp"

namespace appsniff {

namespace {

constexpr std::array<std::string_view, 9> kMethods = {
    "GET ",     "POST ",  "PUT ",   "DELETE ", "HEAD ",
    "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "};

bool starts_with(std::string_view s, std::string_view p) {
  return s.size() >= p.size() && std::memcmp(s.data(), p.data(), p.size()) == 0;
}

bool is_http_port(std::uint16_t p) {
  return p == 80 || p == 8080 || p == 8000 || p == 8008 || p == 8888;
}

}  // namespace

bool try_parse_http(const PacketView& pkt) {
  if (pkt.proto != IpProto::Tcp) return false;
  if (pkt.payload.size() < 16) return false;
  // Restrict to common HTTP ports to reduce false positives.
  if (!is_http_port(pkt.src_port) && !is_http_port(pkt.dst_port)) return false;

  std::string_view sv(reinterpret_cast<const char*>(pkt.payload.data()),
                      pkt.payload.size());

  // Detect HTTP/2 preface and let http2 parser handle it.
  if (starts_with(sv, "PRI * HTTP/2.0")) return false;

  bool is_request = false;
  for (auto m : kMethods) {
    if (starts_with(sv, m)) {
      is_request = true;
      break;
    }
  }
  const bool is_response =
      starts_with(sv, "HTTP/1.0 ") || starts_with(sv, "HTTP/1.1 ");
  if (!is_request && !is_response) return false;

  // Extract first line.
  auto eol = sv.find("\r\n");
  if (eol == std::string_view::npos)
    eol = std::min<std::size_t>(sv.size(), 200);
  std::string first_line(sv.substr(0, eol));

  // Try to grab Host header for requests.
  std::string host;
  if (is_request) {
    auto h = sv.find("\r\nHost:");
    if (h != std::string_view::npos) {
      const auto start = h + 7;
      const auto end = sv.find("\r\n", start);
      host = std::string(sv.substr(start, end - start));
      // trim leading spaces
      while (!host.empty() &&
             std::isspace(static_cast<unsigned char>(host.front())))
        host.erase(host.begin());
    }
  }

  std::ostringstream info;
  info << (is_request ? "REQ  " : "RESP ") << first_line;
  if (!host.empty()) info << "  (Host:" << host << ')';

  log_line("HTTP", pkt, info.str());
  return true;
}

}  // namespace appsniff
