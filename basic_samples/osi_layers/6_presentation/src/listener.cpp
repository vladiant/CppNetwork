#include "listener.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <format>
#include <iostream>
#include <string>
#include <string_view>

#include "compression.h"
#include "encoding.h"
#include "raii.h"

namespace presentation {

namespace {

void print_openssl_error(std::string_view what) {
  std::cerr << std::format("[listener] {}: ", what);
  ERR_print_errors_fp(stderr);
}

struct CertKey {
  X509Ptr cert;
  EvpPKeyPtr key;

  [[nodiscard]] bool valid() const noexcept { return cert && key; }
};

[[nodiscard]] CertKey make_self_signed_cert() {
  CertKey ck;
  ck.key.reset(EVP_RSA_gen(2048));
  if (!ck.key) {
    print_openssl_error("EVP_RSA_gen");
    return ck;
  }
  ck.cert.reset(X509_new());
  if (!ck.cert) {
    print_openssl_error("X509_new");
    ck.key.reset();
    return ck;
  }

  auto* x509 = ck.cert.get();
  X509_set_version(x509, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
  X509_gmtime_adj(X509_getm_notBefore(x509), 0);
  X509_gmtime_adj(X509_getm_notAfter(x509), 60L * 60L * 24L * 365L);
  X509_set_pubkey(x509, ck.key.get());

  auto add_name = [](X509_NAME* name, const char* field, std::string_view v) {
    X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(v.data()),
                               static_cast<int>(v.size()), -1, 0);
  };

  X509_NAME* name = X509_get_subject_name(x509);
  add_name(name, "C", "XX");
  add_name(name, "O", "OSI Demo");
  add_name(name, "CN", "localhost");
  X509_set_issuer_name(x509, name);

  if (!X509_sign(x509, ck.key.get(), EVP_sha256())) {
    print_openssl_error("X509_sign");
    ck.cert.reset();
    ck.key.reset();
  }
  return ck;
}

[[nodiscard]] SslCtxPtr make_server_ctx(const CertKey& ck) {
  SslCtxPtr ctx{SSL_CTX_new(TLS_server_method())};
  if (!ctx) {
    print_openssl_error("SSL_CTX_new");
    return ctx;
  }
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
#ifdef TLS1_3_VERSION
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
#endif
  if (SSL_CTX_use_certificate(ctx.get(), ck.cert.get()) != 1 ||
      SSL_CTX_use_PrivateKey(ctx.get(), ck.key.get()) != 1 ||
      SSL_CTX_check_private_key(ctx.get()) != 1) {
    print_openssl_error("loading cert/key");
    ctx.reset();
  }
  return ctx;
}

[[nodiscard]] FileDescriptor open_listening_socket(std::uint16_t port) {
  FileDescriptor sock{::socket(AF_INET, SOCK_STREAM, 0)};
  if (!sock) {
    std::perror("[listener] socket");
    return {};
  }
  int yes = 1;
  setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(sock.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) <
      0) {
    std::perror("[listener] bind");
    return {};
  }
  if (::listen(sock.get(), 1) < 0) {
    std::perror("[listener] listen");
    return {};
  }
  return sock;
}

void report_payload(ByteView payload) {
  std::cout << std::format("  bytes        : {}\n", payload.size());

  std::string text;
  text.reserve(payload.size());
  for (auto b : payload) {
    const auto v = static_cast<unsigned char>(b);
    if (v == '\r' || v == '\n') break;
    text += (v >= 0x20 && v < 0x7f) ? static_cast<char>(v) : '.';
  }
  std::cout << std::format("  as text      : \"{}\"\n", text);

  const auto preview = payload.first(std::min<std::size_t>(payload.size(), 32));
  std::cout << std::format("  hex (first {} B): {}\n", preview.size(),
                           to_hex(preview));
  std::cout << std::format("  base64       : {}\n", base64_encode(payload));

  try {
    const auto compressed = zlib_compress(payload);
    const double ratio = payload.empty()
                             ? 0.0
                             : 100.0 * static_cast<double>(compressed.size()) /
                                   static_cast<double>(payload.size());
    std::cout << std::format("  zlib size    : {} B (ratio {:.1f}%)\n",
                             compressed.size(), ratio);
  } catch (const std::exception& e) {
    std::cout << std::format("  zlib         : {}\n", e.what());
  }
}

}  // namespace

int run_listener(std::uint16_t port) {
  std::cout << "=== Presentation Layer TLS Listener ===\n"
               "Generating in-memory self-signed certificate...\n";
  auto ck = make_self_signed_cert();
  if (!ck.valid()) return 1;

  auto ctx = make_server_ctx(ck);
  if (!ctx) return 1;

  auto srv = open_listening_socket(port);
  if (!srv) return 1;

  std::cout << std::format(
      "Listening on 127.0.0.1:{} (waiting for one TLS client)\n"
      "Try:  openssl s_client -connect 127.0.0.1:{} -quiet\n\n",
      port, port);

  sockaddr_in cli{};
  socklen_t cli_len = sizeof(cli);
  FileDescriptor client{
      ::accept(srv.get(), reinterpret_cast<sockaddr*>(&cli), &cli_len)};
  srv.reset();
  if (!client) {
    std::perror("[listener] accept");
    return 1;
  }

  std::array<char, INET_ADDRSTRLEN> ip{};
  inet_ntop(AF_INET, &cli.sin_addr, ip.data(), ip.size());
  std::cout << std::format("Accepted TCP from {}:{}\n", ip.data(),
                           ntohs(cli.sin_port));

  SslPtr ssl{SSL_new(ctx.get())};
  if (!ssl) {
    print_openssl_error("SSL_new");
    return 1;
  }
  SSL_set_fd(ssl.get(), client.get());

  if (SSL_accept(ssl.get()) <= 0) {
    print_openssl_error("SSL_accept");
    return 1;
  }

  std::cout << std::format("TLS handshake OK\n  protocol     : {}\n",
                           SSL_get_version(ssl.get()));
  if (const SSL_CIPHER* c = SSL_get_current_cipher(ssl.get())) {
    std::cout << std::format("  cipher       : {} ({} bits)\n",
                             SSL_CIPHER_get_name(c),
                             SSL_CIPHER_get_bits(c, nullptr));
  }
  std::cout << "\nReading first record from peer...\n";

  Bytes buf(4096);
  const int n = SSL_read(ssl.get(), buf.data(), static_cast<int>(buf.size()));
  if (n > 0) {
    buf.resize(static_cast<std::size_t>(n));
    report_payload(buf);
  } else {
    std::cout << "  (no data received)\n";
  }

  constexpr std::string_view ack =
      "HTTP/1.0 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Connection: close\r\n"
      "\r\n"
      "OSI Layer 6 listener: payload received.\n";
  SSL_write(ssl.get(), ack.data(), static_cast<int>(ack.size()));
  SSL_shutdown(ssl.get());

  std::cout << "\nConnection closed.\n";
  return 0;
}

}  // namespace presentation
