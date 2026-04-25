#include <arpa/nameser.h>

#include <sstream>
#include <string>

#include "../packet.hpp"

namespace appsniff {

namespace {

bool is_dns_port(std::uint16_t p) {
  return p == 53 || p == 5353 /* mDNS */ || p == 5355 /* LLMNR */;
}

const char* opcode_name(std::uint8_t op) {
  switch (op) {
    case ns_o_query:
      return "QUERY";
    case ns_o_iquery:
      return "IQUERY";
    case ns_o_status:
      return "STATUS";
    case ns_o_notify:
      return "NOTIFY";
    case ns_o_update:
      return "UPDATE";
    default:
      return "OP?";
  }
}

const char* rcode_name(std::uint8_t rc) {
  switch (rc) {
    case ns_r_noerror:
      return "NOERROR";
    case ns_r_formerr:
      return "FORMERR";
    case ns_r_servfail:
      return "SERVFAIL";
    case ns_r_nxdomain:
      return "NXDOMAIN";
    case ns_r_notimpl:
      return "NOTIMP";
    case ns_r_refused:
      return "REFUSED";
    default:
      return "RCODE?";
  }
}

const char* qtype_name(std::uint16_t t) {
  switch (t) {
    case ns_t_a:
      return "A";
    case ns_t_ns:
      return "NS";
    case ns_t_cname:
      return "CNAME";
    case ns_t_soa:
      return "SOA";
    case ns_t_ptr:
      return "PTR";
    case ns_t_mx:
      return "MX";
    case ns_t_txt:
      return "TXT";
    case ns_t_aaaa:
      return "AAAA";
    case ns_t_srv:
      return "SRV";
    case ns_t_naptr:
      return "NAPTR";
    case ns_t_opt:
      return "OPT";
    case ns_t_ds:
      return "DS";
    case ns_t_rrsig:
      return "RRSIG";
    case ns_t_dnskey:
      return "DNSKEY";
    case 64:
      return "SVCB";  // not in older nameser.h
    case 65:
      return "HTTPS";  // not in older nameser.h
    case ns_t_any:
      return "ANY";
    default:
      return "TYPE?";
  }
}

// Parses a DNS QNAME starting at offset `off` in `d`. Supports compression
// pointers but bounds-checks aggressively. Returns the next offset after the
// (uncompressed) name in `next_off`. Returns empty string on failure.
std::string parse_qname(const std::uint8_t* d, std::size_t len, std::size_t off,
                        std::size_t& next_off) {
  std::string out;
  std::size_t cur = off;
  bool jumped = false;
  std::size_t hops = 0;
  next_off = off;

  while (cur < len) {
    const std::uint8_t l = d[cur];
    if (l == 0) {
      if (!jumped) next_off = cur + 1;
      return out.empty() ? std::string(".") : out;
    }
    if ((l & 0xC0) == 0xC0) {
      if (cur + 1 >= len) return {};
      if (!jumped) next_off = cur + 2;
      const std::size_t ptr = ((l & 0x3F) << 8) | d[cur + 1];
      if (ptr >= len || ++hops > 16) return {};
      cur = ptr;
      jumped = true;
      continue;
    }
    if ((l & 0xC0) != 0) return {};  // reserved
    if (cur + 1 + l > len) return {};
    if (!out.empty()) out += '.';
    out.append(reinterpret_cast<const char*>(d + cur + 1), l);
    cur += 1 + l;
    if (out.size() > 255) return {};
  }
  return {};
}

}  // namespace

bool try_parse_dns(const PacketView& pkt) {
  if (pkt.proto != IpProto::Udp) return false;  // skip TCP DNS for simplicity
  if (!is_dns_port(pkt.src_port) && !is_dns_port(pkt.dst_port)) return false;
  const auto& payload = pkt.payload;
  if (payload.size() < 12) return false;

  const std::uint8_t* d = payload.data();
  const std::size_t n = payload.size();

  const std::uint16_t id = static_cast<std::uint16_t>((d[0] << 8) | d[1]);
  const std::uint16_t flags = static_cast<std::uint16_t>((d[2] << 8) | d[3]);
  const std::uint16_t qdcount = static_cast<std::uint16_t>((d[4] << 8) | d[5]);
  const std::uint16_t ancount = static_cast<std::uint16_t>((d[6] << 8) | d[7]);

  const bool qr = (flags & 0x8000) != 0;
  const std::uint8_t opcode = static_cast<std::uint8_t>((flags >> 11) & 0x0F);
  const std::uint8_t rcode = static_cast<std::uint8_t>(flags & 0x0F);

  std::ostringstream info;
  info << (qr ? "RESP" : "QUERY") << " id=0x" << std::hex << id << std::dec
       << " op=" << opcode_name(opcode);
  if (qr) info << " rcode=" << rcode_name(rcode);
  info << " qd=" << qdcount << " an=" << ancount;

  if (qdcount > 0) {
    std::size_t off = 12;
    std::size_t next = 0;
    const std::string qname = parse_qname(d, n, off, next);
    if (!qname.empty() && next + 4 <= n) {
      const std::uint16_t qtype =
          static_cast<std::uint16_t>((d[next] << 8) | d[next + 1]);
      info << "  q=" << qname << '/' << qtype_name(qtype);
    }
  }

  log_line("DNS", pkt, info.str());
  return true;
}

}  // namespace appsniff
