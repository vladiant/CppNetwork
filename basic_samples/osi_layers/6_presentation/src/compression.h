#pragma once

#include "encoding.h"

namespace presentation {

[[nodiscard]] Bytes zlib_compress(ByteView data, int level = 6);
[[nodiscard]] Bytes zlib_decompress(ByteView data, std::size_t expected_size);

void demonstrate_compression();

}  // namespace presentation
