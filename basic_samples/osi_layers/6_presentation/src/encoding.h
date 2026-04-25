#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace presentation {

using ByteView = std::span<const std::byte>;
using Bytes = std::vector<std::byte>;

[[nodiscard]] std::string base64_encode(ByteView data);
[[nodiscard]] Bytes base64_decode(std::string_view encoded);

[[nodiscard]] std::string to_hex(ByteView data);

[[nodiscard]] inline ByteView as_bytes(std::string_view s) noexcept {
  return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

void demonstrate_encoding();

}  // namespace presentation
