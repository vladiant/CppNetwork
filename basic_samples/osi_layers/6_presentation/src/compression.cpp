#include "compression.h"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <format>
#include <iostream>
#include <stdexcept>
#include <string>

namespace presentation {

Bytes zlib_compress(ByteView data, int level) {
  uLongf bound = compressBound(static_cast<uLong>(data.size()));
  Bytes out(bound);
  const int rc = compress2(reinterpret_cast<Bytef*>(out.data()), &bound,
                           reinterpret_cast<const Bytef*>(data.data()),
                           static_cast<uLong>(data.size()), level);
  if (rc != Z_OK) {
    throw std::runtime_error(std::format("zlib compress failed: {}", rc));
  }
  out.resize(bound);
  return out;
}

Bytes zlib_decompress(ByteView data, std::size_t expected_size) {
  Bytes out(expected_size);
  auto dest_len = static_cast<uLongf>(expected_size);
  const int rc = uncompress(reinterpret_cast<Bytef*>(out.data()), &dest_len,
                            reinterpret_cast<const Bytef*>(data.data()),
                            static_cast<uLong>(data.size()));
  if (rc != Z_OK) {
    throw std::runtime_error(std::format("zlib uncompress failed: {}", rc));
  }
  out.resize(dest_len);
  return out;
}

void demonstrate_compression() {
  std::cout << "=== Compression (zlib / DEFLATE) ===\n";
  std::cout << std::format("zlib version : {}\n", zlibVersion());

  std::string text;
  text.reserve(50 * 56);
  for (int i = 0; i < 50; ++i) {
    text += "The OSI Presentation Layer handles syntax and semantics. ";
  }
  const auto raw = as_bytes(text);

  constexpr std::array levels{1, 6, 9};
  for (int level : levels) {
    const auto compressed = zlib_compress(raw, level);
    const auto decompressed = zlib_decompress(compressed, raw.size());
    const double ratio = 100.0 * static_cast<double>(compressed.size()) /
                         static_cast<double>(raw.size());
    const bool ok = std::equal(raw.begin(), raw.end(), decompressed.begin(),
                               decompressed.end());
    std::cout << std::format(
        "  level={}  original={} B  compressed={} B  ratio={:.1f}%  "
        "round-trip={}\n",
        level, raw.size(), compressed.size(), ratio, ok ? "OK" : "FAIL");
  }
  std::cout << '\n';
}

}  // namespace presentation
