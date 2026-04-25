#include "sniffer.hpp"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>

#include "packet.hpp"

namespace appsniff {

namespace {

// EtherType values come from <net/ethernet.h>:
//   ETHERTYPE_IP   (0x0800), ETHERTYPE_IPV6 (0x86DD), ETHERTYPE_VLAN (0x8100).

std::mutex g_log_mtx;

std::string ipv4_to_string(std::uint32_t addr_be) {
  char buf[INET_ADDRSTRLEN] = {};
  ::inet_ntop(AF_INET, &addr_be, buf, sizeof(buf));
  return buf;
}

std::string ipv6_to_string(const std::uint8_t addr[16]) {
  char buf[INET6_ADDRSTRLEN] = {};
  ::inet_ntop(AF_INET6, addr, buf, sizeof(buf));
  return buf;
}

std::string format_timestamp(const timeval& tv) {
  std::time_t secs = tv.tv_sec;
  std::tm tmv{};
  ::localtime_r(&secs, &tmv);
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%06ld", tmv.tm_hour,
                tmv.tm_min, tmv.tm_sec, static_cast<long>(tv.tv_usec));
  return buf;
}

void dispatch(const PacketView& pkt) {
  // Order matters: more specific protocols first.
  if (try_parse_dns(pkt)) return;
  if (try_parse_quic(pkt)) return;
  if (try_parse_tls(pkt)) return;
  if (try_parse_http2(pkt)) return;
  if (try_parse_http(pkt)) return;
  if (try_parse_smtp(pkt)) return;
  if (try_parse_mqtt(pkt)) return;
  if (try_parse_rtp(pkt)) return;
}

}  // namespace

std::string hex_dump_short(std::span<const std::uint8_t> data,
                           std::size_t max_bytes) {
  std::ostringstream os;
  const auto n = std::min(data.size(), max_bytes);
  for (std::size_t i = 0; i < n; ++i) {
    if (i) os << ' ';
    os << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<unsigned>(data[i]);
  }
  if (data.size() > n) os << " ...";
  return os.str();
}

std::string printable_preview(std::span<const std::uint8_t> data,
                              std::size_t max_bytes) {
  std::string out;
  const auto n = std::min(data.size(), max_bytes);
  out.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    const auto c = static_cast<char>(data[i]);
    if (c == '\r')
      out += "\\r";
    else if (c == '\n')
      out += "\\n";
    else if (c == '\t')
      out += "\\t";
    else if (c >= 0x20 && c < 0x7F)
      out += c;
    else
      out += '.';
  }
  if (data.size() > n) out += "...";
  return out;
}

void log_line(std::string_view proto, const PacketView& pkt,
              std::string_view info) {
  std::scoped_lock lk(g_log_mtx);
  std::cout << '[' << pkt.timestamp << "] " << std::left << std::setw(6)
            << proto << " " << pkt.src_ip << ':' << pkt.src_port << " -> "
            << pkt.dst_ip << ':' << pkt.dst_port << "  " << info << '\n';
  std::cout.flush();
}

struct Sniffer::Impl {
  SnifferOptions opts;
  pcap_t* handle = nullptr;
  int datalink = DLT_EN10MB;
};

Sniffer::Sniffer(SnifferOptions opts) : impl_(new Impl{}) {
  impl_->opts = std::move(opts);
}

Sniffer::~Sniffer() {
  if (impl_) {
    if (impl_->handle) pcap_close(impl_->handle);
    delete impl_;
  }
}

void Sniffer::stop() {
  running_.store(false);
  if (impl_ && impl_->handle) {
    pcap_breakloop(impl_->handle);
  }
}

namespace {

// Parse from L3 onward and dispatch.
void handle_l3(const std::uint8_t* l3, std::size_t l3_len,
               std::uint16_t ethertype, const std::string& ts) {
  PacketView pkt;
  pkt.timestamp = ts;

  const std::uint8_t* l4 = nullptr;
  std::size_t l4_len = 0;

  if (ethertype == ETHERTYPE_IP) {
    if (l3_len < 20) return;
    const std::uint8_t ihl = static_cast<std::uint8_t>((l3[0] & 0x0F) * 4u);
    if (ihl < 20 || l3_len < ihl) return;
    const std::uint16_t total =
        static_cast<std::uint16_t>((l3[2] << 8) | l3[3]);
    if (total > l3_len || total < ihl) return;
    const std::uint8_t proto = l3[9];
    std::uint32_t src_be = 0, dst_be = 0;
    std::memcpy(&src_be, l3 + 12, 4);
    std::memcpy(&dst_be, l3 + 16, 4);
    pkt.src_ip = ipv4_to_string(src_be);
    pkt.dst_ip = ipv4_to_string(dst_be);

    // Skip fragmented packets (offset != 0 or MF set).
    const std::uint16_t frag = static_cast<std::uint16_t>((l3[6] << 8) | l3[7]);
    if ((frag & 0x1FFF) != 0 || (frag & 0x2000) != 0) return;

    l4 = l3 + ihl;
    l4_len = static_cast<std::size_t>(total - ihl);
    if (proto == IPPROTO_TCP)
      pkt.proto = IpProto::Tcp;
    else if (proto == IPPROTO_UDP)
      pkt.proto = IpProto::Udp;
    else
      return;  // not interested
  } else if (ethertype == ETHERTYPE_IPV6) {
    if (l3_len < 40) return;
    std::uint8_t next = l3[6];
    const std::uint16_t plen = static_cast<std::uint16_t>((l3[4] << 8) | l3[5]);
    std::uint8_t addr_src[16];
    std::memcpy(addr_src, l3 + 8, 16);
    std::uint8_t addr_dst[16];
    std::memcpy(addr_dst, l3 + 24, 16);
    pkt.src_ip = ipv6_to_string(addr_src);
    pkt.dst_ip = ipv6_to_string(addr_dst);

    std::size_t off = 40;
    // Walk a couple of common extension headers.
    for (int i = 0; i < 8; ++i) {
      if (next == IPPROTO_TCP || next == IPPROTO_UDP) break;
      if (next == IPPROTO_HOPOPTS || next == IPPROTO_ROUTING ||
          next == IPPROTO_DSTOPTS) {
        if (off + 2 > l3_len) return;
        const std::uint8_t nh = l3[off];
        const std::size_t hdr_len = (l3[off + 1] + 1u) * 8u;
        if (off + hdr_len > l3_len) return;
        next = nh;
        off += hdr_len;
      } else {
        return;
      }
    }
    if (next == IPPROTO_TCP)
      pkt.proto = IpProto::Tcp;
    else if (next == IPPROTO_UDP)
      pkt.proto = IpProto::Udp;
    else
      return;

    const std::size_t avail = std::min<std::size_t>(plen, l3_len - 40);
    l4 = l3 + off;
    if (off > l3_len) return;
    l4_len = avail - (off - 40);
  } else {
    return;
  }

  const std::uint8_t* payload = nullptr;
  std::size_t payload_len = 0;

  if (pkt.proto == IpProto::Tcp) {
    if (l4_len < 20) return;
    pkt.src_port = static_cast<std::uint16_t>((l4[0] << 8) | l4[1]);
    pkt.dst_port = static_cast<std::uint16_t>((l4[2] << 8) | l4[3]);
    const std::size_t doff = ((l4[12] >> 4) & 0x0F) * 4u;
    if (doff < 20 || l4_len < doff) return;
    payload = l4 + doff;
    payload_len = l4_len - doff;
  } else {  // UDP
    if (l4_len < 8) return;
    pkt.src_port = static_cast<std::uint16_t>((l4[0] << 8) | l4[1]);
    pkt.dst_port = static_cast<std::uint16_t>((l4[2] << 8) | l4[3]);
    payload = l4 + 8;
    payload_len = l4_len - 8;
  }

  if (payload_len == 0) return;
  pkt.payload = std::span<const std::uint8_t>(payload, payload_len);
  dispatch(pkt);
}

void packet_callback(std::uint8_t* user, const struct pcap_pkthdr* hdr,
                     const std::uint8_t* bytes) {
  const int dlt = *reinterpret_cast<int*>(user);
  const std::string ts = format_timestamp(hdr->ts);

  const std::uint8_t* p = bytes;
  std::size_t len = hdr->caplen;

  std::uint16_t ethertype = 0;

  if (dlt == DLT_EN10MB) {
    if (len < 14) return;
    ethertype = static_cast<std::uint16_t>((p[12] << 8) | p[13]);
    p += 14;
    len -= 14;
    // Skip up to two VLAN tags.
    for (int i = 0; i < 2 && ethertype == ETHERTYPE_VLAN; ++i) {
      if (len < 4) return;
      ethertype = static_cast<std::uint16_t>((p[2] << 8) | p[3]);
      p += 4;
      len -= 4;
    }
  } else if (dlt == DLT_LINUX_SLL) {
    if (len < 16) return;
    ethertype = static_cast<std::uint16_t>((p[14] << 8) | p[15]);
    p += 16;
    len -= 16;
  } else if (dlt == DLT_LINUX_SLL2) {
    if (len < 20) return;
    ethertype = static_cast<std::uint16_t>((p[0] << 8) | p[1]);
    p += 20;
    len -= 20;
  } else if (dlt == DLT_RAW) {
    if (len < 1) return;
    const std::uint8_t v = (p[0] >> 4) & 0x0F;
    ethertype = (v == 6) ? ETHERTYPE_IPV6 : ETHERTYPE_IP;
  } else {
    return;  // unsupported link type
  }

  handle_l3(p, len, ethertype, ts);
}

}  // namespace

void Sniffer::run() {
  char errbuf[PCAP_ERRBUF_SIZE] = {};

  std::string iface = impl_->opts.interface;
  if (iface.empty()) {
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
      throw std::runtime_error(std::string("pcap_findalldevs failed: ") +
                               errbuf);
    }
    iface = alldevs->name;
    std::cerr << "[info] auto-selected interface: " << iface << '\n';
    pcap_freealldevs(alldevs);
  }

  impl_->handle = pcap_create(iface.c_str(), errbuf);
  if (!impl_->handle) {
    throw std::runtime_error(std::string("pcap_create failed: ") + errbuf);
  }
  pcap_set_snaplen(impl_->handle, impl_->opts.snaplen);
  pcap_set_promisc(impl_->handle, impl_->opts.promiscuous ? 1 : 0);
  pcap_set_timeout(impl_->handle, impl_->opts.timeout_ms);
  pcap_set_immediate_mode(impl_->handle, 1);

  if (int rc = pcap_activate(impl_->handle); rc < 0) {
    throw std::runtime_error(std::string("pcap_activate failed: ") +
                             pcap_geterr(impl_->handle));
  } else if (rc > 0) {
    std::cerr << "[warn] pcap_activate: " << pcap_statustostr(rc) << '\n';
  }

  impl_->datalink = pcap_datalink(impl_->handle);

  if (!impl_->opts.bpf_filter.empty()) {
    bpf_program prog{};
    if (pcap_compile(impl_->handle, &prog, impl_->opts.bpf_filter.c_str(), 1,
                     PCAP_NETMASK_UNKNOWN) != 0) {
      throw std::runtime_error(std::string("pcap_compile: ") +
                               pcap_geterr(impl_->handle));
    }
    if (pcap_setfilter(impl_->handle, &prog) != 0) {
      pcap_freecode(&prog);
      throw std::runtime_error(std::string("pcap_setfilter: ") +
                               pcap_geterr(impl_->handle));
    }
    pcap_freecode(&prog);
  }

  std::cerr << "[info] capturing on " << iface
            << " (datalink=" << pcap_datalink_val_to_name(impl_->datalink)
            << "). Press Ctrl+C to stop.\n";

  running_.store(true);
  int rc = pcap_loop(impl_->handle, -1, packet_callback,
                     reinterpret_cast<std::uint8_t*>(&impl_->datalink));
  running_.store(false);

  if (rc == -1) {
    throw std::runtime_error(std::string("pcap_loop: ") +
                             pcap_geterr(impl_->handle));
  }
}

}  // namespace appsniff
