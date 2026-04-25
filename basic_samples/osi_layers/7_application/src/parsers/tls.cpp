#include <sstream>
#include <string>

#include "../packet.hpp"

namespace appsniff {

namespace {

const char* content_type_name(std::uint8_t t) {
  switch (t) {
    case 20:
      return "ChangeCipherSpec";
    case 21:
      return "Alert";
    case 22:
      return "Handshake";
    case 23:
      return "ApplicationData";
    case 24:
      return "Heartbeat";
    default:
      return "TLS?";
  }
}

const char* handshake_type_name(std::uint8_t t) {
  switch (t) {
    case 1:
      return "ClientHello";
    case 2:
      return "ServerHello";
    case 4:
      return "NewSessionTicket";
    case 8:
      return "EncryptedExtensions";
    case 11:
      return "Certificate";
    case 12:
      return "ServerKeyExchange";
    case 13:
      return "CertificateRequest";
    case 14:
      return "ServerHelloDone";
    case 15:
      return "CertificateVerify";
    case 16:
      return "ClientKeyExchange";
    case 20:
      return "Finished";
    default:
      return "Handshake?";
  }
}

const char* version_name(std::uint16_t v) {
  switch (v) {
    case 0x0301:
      return "TLS1.0";
    case 0x0302:
      return "TLS1.1";
    case 0x0303:
      return "TLS1.2";
    case 0x0304:
      return "TLS1.3";
    default:
      return "TLS?";
  }
}

// Try to extract SNI (Server Name Indication) from a ClientHello body.
// `body` points to ClientHello body (after handshake type/length).
std::string extract_sni(const std::uint8_t* body, std::size_t blen) {
  std::size_t off = 0;
  if (blen < 34) return {};
  off += 2;   // legacy_version
  off += 32;  // random
  if (off + 1 > blen) return {};
  const std::size_t sid_len = body[off++];
  off += sid_len;
  if (off + 2 > blen) return {};
  const std::size_t cs_len = (body[off] << 8) | body[off + 1];
  off += 2 + cs_len;
  if (off + 1 > blen) return {};
  const std::size_t cm_len = body[off++];
  off += cm_len;
  if (off + 2 > blen) return {};
  const std::size_t ext_total = (body[off] << 8) | body[off + 1];
  off += 2;
  if (off + ext_total > blen) return {};
  const std::size_t ext_end = off + ext_total;
  while (off + 4 <= ext_end) {
    const std::uint16_t etype =
        static_cast<std::uint16_t>((body[off] << 8) | body[off + 1]);
    const std::uint16_t elen =
        static_cast<std::uint16_t>((body[off + 2] << 8) | body[off + 3]);
    off += 4;
    if (off + elen > ext_end) return {};
    if (etype == 0x0000 /* server_name */ && elen >= 5) {
      // server_name_list <2 bytes>, name_type <1>, name_len <2>, name
      const std::size_t list_len = (body[off] << 8) | body[off + 1];
      if (list_len + 2 > elen) return {};
      std::size_t p = off + 2;
      const std::size_t list_end = off + 2 + list_len;
      while (p + 3 <= list_end) {
        const std::uint8_t ntype = body[p++];
        const std::uint16_t nlen =
            static_cast<std::uint16_t>((body[p] << 8) | body[p + 1]);
        p += 2;
        if (p + nlen > list_end) return {};
        if (ntype == 0) {
          return std::string(reinterpret_cast<const char*>(body + p), nlen);
        }
        p += nlen;
      }
    }
    off += elen;
  }
  return {};
}

bool plausible_tls_port(std::uint16_t p) {
  // Catch common TLS ports; STARTTLS-on-other-ports won't be caught but
  // we'd false-positive on too much otherwise.
  switch (p) {
    case 443:
    case 465:
    case 563:
    case 587:
    case 636:
    case 853:
    case 989:
    case 990:
    case 992:
    case 993:
    case 994:
    case 995:
    case 5061:
    case 8443:
      return true;
  }
  return false;
}

}  // namespace

bool try_parse_tls(const PacketView& pkt) {
  if (pkt.proto != IpProto::Tcp) return false;
  if (!plausible_tls_port(pkt.src_port) && !plausible_tls_port(pkt.dst_port))
    return false;

  const auto& d = pkt.payload;
  if (d.size() < 5) return false;

  const std::uint8_t ctype = d[0];
  const std::uint16_t legacy = static_cast<std::uint16_t>((d[1] << 8) | d[2]);
  const std::uint16_t rlen = static_cast<std::uint16_t>((d[3] << 8) | d[4]);

  if (ctype < 20 || ctype > 24) return false;
  if (legacy < 0x0300 || legacy > 0x0304) return false;
  if (rlen == 0 || rlen > 0x4000 + 256) return false;

  std::ostringstream info;
  info << content_type_name(ctype) << " " << version_name(legacy)
       << " len=" << rlen;

  if (ctype == 22 /* Handshake */ && d.size() >= 5 + 4) {
    const std::uint8_t ht = d[5];
    const std::uint32_t hlen = (static_cast<std::uint32_t>(d[6]) << 16) |
                               (static_cast<std::uint32_t>(d[7]) << 8) |
                               static_cast<std::uint32_t>(d[8]);
    info << " " << handshake_type_name(ht);

    const std::size_t body_off = 9;
    const std::size_t body_avail =
        (d.size() > body_off) ? std::min<std::size_t>(d.size() - body_off, hlen)
                              : 0;

    if (ht == 1 /* ClientHello */ && body_avail >= 38) {
      const auto sni = extract_sni(d.data() + body_off, body_avail);
      if (!sni.empty()) info << " SNI=" << sni;
    }
    if ((ht == 1 || ht == 2) && body_avail >= 2) {
      const std::uint16_t inner =
          static_cast<std::uint16_t>((d[body_off] << 8) | d[body_off + 1]);
      info << " ver=" << version_name(inner);
    }
  }

  log_line("TLS", pkt, info.str());
  return true;
}

}  // namespace appsniff
