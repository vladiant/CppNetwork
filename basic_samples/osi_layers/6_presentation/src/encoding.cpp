#include "encoding.h"

#include <openssl/evp.h>

#include <algorithm>
#include <format>
#include <iostream>

namespace presentation {

std::string base64_encode(ByteView data) {
  if (data.empty()) return {};
  const auto input_size = static_cast<int>(data.size());
  const auto output_size = 4 * ((input_size + 2) / 3);
  std::string out(static_cast<std::size_t>(output_size), '\0');
  const int written = EVP_EncodeBlock(
      reinterpret_cast<unsigned char*>(out.data()),
      reinterpret_cast<const unsigned char*>(data.data()), input_size);
  out.resize(static_cast<std::size_t>(written));
  return out;
}

Bytes base64_decode(std::string_view encoded) {
  if (encoded.empty()) return {};
  Bytes out(encoded.size());
  const int written =
      EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                      reinterpret_cast<const unsigned char*>(encoded.data()),
                      static_cast<int>(encoded.size()));
  if (written < 0) return {};

  const auto padding = std::ranges::count(encoded, '=');
  out.resize(static_cast<std::size_t>(written) -
             static_cast<std::size_t>(padding));
  return out;
}

std::string to_hex(ByteView data) {
  std::string out;
  out.reserve(data.size() * 3);
  for (auto b : data) {
    out += std::format("{:02x} ", static_cast<unsigned>(b));
  }
  return out;
}

void demonstrate_encoding() {
  std::cout << "=== Encoding (character set & binary-to-text) ===\n";
  constexpr std::string_view ascii_text = "Hello, OSI!";
  constexpr std::string_view utf8_text = "Héllo, OSI — Καλημέρα 🌐";

  std::cout << std::format("ASCII string : \"{}\" ({} bytes)\n", ascii_text,
                           ascii_text.size());
  std::cout << std::format("UTF-8 string : \"{}\" ({} bytes)\n", utf8_text,
                           utf8_text.size());

  const auto bytes = as_bytes(utf8_text);
  std::cout << std::format("UTF-8 hex    : {}\n", to_hex(bytes));

  const auto encoded = base64_encode(bytes);
  std::cout << std::format("Base64       : {}\n", encoded);

  const auto decoded = base64_decode(encoded);
  const std::string_view round_trip{
      reinterpret_cast<const char*>(decoded.data()), decoded.size()};
  std::cout << std::format("Round-trip   : \"{}\" [{}]\n\n", round_trip,
                           round_trip == utf8_text ? "OK" : "FAIL");
}

}  // namespace presentation
