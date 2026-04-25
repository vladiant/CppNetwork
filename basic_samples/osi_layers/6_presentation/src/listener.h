#pragma once

#include <cstdint>

namespace presentation {

// Run a single-connection TLS listener on 127.0.0.1:<port>.
// Generates a self-signed certificate in memory.
// Logs negotiated TLS protocol/cipher and presentation-layer details
// (hex, Base64, zlib compression ratio) of the first received payload,
// then sends a small acknowledgement and exits.
//
// Returns 0 on success, non-zero on error.
int run_listener(uint16_t port);

}  // namespace presentation
