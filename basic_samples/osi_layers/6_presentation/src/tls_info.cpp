#include "tls_info.h"

#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#include <algorithm>
#include <format>
#include <iostream>
#include <string_view>

#include "raii.h"

namespace presentation {

namespace {

[[nodiscard]] constexpr std::string_view protocol_name(int version) noexcept {
  switch (version) {
    case TLS1_VERSION:
      return "TLS 1.0";
    case TLS1_1_VERSION:
      return "TLS 1.1";
    case TLS1_2_VERSION:
      return "TLS 1.2";
#ifdef TLS1_3_VERSION
    case TLS1_3_VERSION:
      return "TLS 1.3";
#endif
    default:
      return "unknown";
  }
}

}  // namespace

void demonstrate_tls() {
  std::cout << "=== TLS (Transport Layer Security) ===\n";
  std::cout << std::format("OpenSSL      : {}\n",
                           OpenSSL_version(OPENSSL_VERSION));

  SslCtxPtr ctx{SSL_CTX_new(TLS_client_method())};
  if (!ctx) {
    std::cout << "Failed to create SSL_CTX\n\n";
    return;
  }

  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
#ifdef TLS1_3_VERSION
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
#endif

  std::cout << std::format(
      "Min protocol : {}\n",
      protocol_name(SSL_CTX_get_min_proto_version(ctx.get())));
  std::cout << std::format(
      "Max protocol : {}\n",
      protocol_name(SSL_CTX_get_max_proto_version(ctx.get())));

  SslPtr ssl{SSL_new(ctx.get())};
  if (!ssl) {
    std::cout << "Failed to create SSL object\n\n";
    return;
  }

  STACK_OF(SSL_CIPHER)* ciphers = SSL_get1_supported_ciphers(ssl.get());
  if (ciphers) {
    const int n = sk_SSL_CIPHER_num(ciphers);
    std::cout << std::format("Cipher suites: {} available\n", n);
    constexpr int kMaxShown = 8;
    const int show = std::min(n, kMaxShown);
    for (int i = 0; i < show; ++i) {
      const SSL_CIPHER* c = sk_SSL_CIPHER_value(ciphers, i);
      std::cout << std::format(
          "  - {}  ({}, {} bits)\n", SSL_CIPHER_get_name(c),
          SSL_CIPHER_get_version(c), SSL_CIPHER_get_bits(c, nullptr));
    }
    if (n > show) {
      std::cout << std::format("  ... ({} more)\n", n - show);
    }
    sk_SSL_CIPHER_free(ciphers);
  }
  std::cout << '\n';
}

}  // namespace presentation
