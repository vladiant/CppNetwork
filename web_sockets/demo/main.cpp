/*
 * WebSocket from scratch — RFC 6455 implementation
 * Server and client in a single file, launched via fork().
 *
 * Build:
 *   g++ -std=c++17 -O2 -Wall -o websocket_demo websocket_demo.cpp -lpthread
 * Run:
 *   ./websocket_demo
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// ======================
// Constants
// ======================

static constexpr const char* WS_HOST = "127.0.0.1";
static constexpr int WS_PORT = 8765;
static constexpr const char* WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static constexpr uint8_t OP_CONTINUATION = 0x0;
static constexpr uint8_t OP_TEXT = 0x1;
static constexpr uint8_t OP_BINARY = 0x2;
static constexpr uint8_t OP_CLOSE = 0x8;
static constexpr uint8_t OP_PING = 0x9;
static constexpr uint8_t OP_PONG = 0xA;

static constexpr uint16_t CLOSE_NORMAL = 1000;
static constexpr uint16_t CLOSE_PROTO_ERROR = 1002;
static constexpr uint16_t CLOSE_INVALID_UTF8 = 1007;
static constexpr uint16_t CLOSE_TOO_BIG = 1009;

static constexpr size_t MAX_PAYLOAD = 1 * 1024 * 1024;  // 1 MB

// ======================
// Logging
// ======================

static std::mutex g_log_mutex;

static void ws_log(const std::string& side, const std::string& dir,
                   const std::string& level, const std::string& msg) {
  // Timestamp HH:MM:SS.mmm
  auto now = std::chrono::system_clock::now();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm_info{};
  localtime_r(&t, &tm_info);

  std::lock_guard<std::mutex> lock(g_log_mutex);
  std::cout << std::put_time(&tm_info, "[%H:%M:%S") << '.' << std::setfill('0')
            << std::setw(3) << ms.count() << "] " << std::left << std::setw(6)
            << side << ' ' << std::setw(2) << dir << " [" << level << "] "
            << msg << std::endl;
}

// ======================
// SHA-1 (RFC 3174)
// ======================

struct SHA1_CTX {
  uint32_t state[5];
  uint64_t count;
  uint8_t buf[64];
  uint32_t buf_len;
};

static inline uint32_t sha1_rol(uint32_t x, unsigned n) {
  return (x << n) | (x >> (32 - n));
}

static void sha1_compress(SHA1_CTX& ctx, const uint8_t* block) {
  uint32_t w[80];
  for (int i = 0; i < 16; ++i)
    w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
           (uint32_t(block[i * 4 + 2]) << 8) | (uint32_t(block[i * 4 + 3]));
  for (int i = 16; i < 80; ++i)
    w[i] = sha1_rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

  uint32_t a = ctx.state[0], b = ctx.state[1], c = ctx.state[2],
           d = ctx.state[3], e = ctx.state[4];

  for (int i = 0; i < 80; ++i) {
    uint32_t f, k;
    if (i < 20) {
      f = (b & c) | (~b & d);
      k = 0x5A827999u;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1u;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDCu;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6u;
    }
    uint32_t temp = sha1_rol(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = sha1_rol(b, 30);
    b = a;
    a = temp;
  }
  ctx.state[0] += a;
  ctx.state[1] += b;
  ctx.state[2] += c;
  ctx.state[3] += d;
  ctx.state[4] += e;
}

static void sha1_init(SHA1_CTX& ctx) {
  ctx.state[0] = 0x67452301u;
  ctx.state[1] = 0xEFCDAB89u;
  ctx.state[2] = 0x98BADCFEu;
  ctx.state[3] = 0x10325476u;
  ctx.state[4] = 0xC3D2E1F0u;
  ctx.count = 0;
  ctx.buf_len = 0;
}

static void sha1_update(SHA1_CTX& ctx, const uint8_t* data, size_t len) {
  ctx.count += len * 8;
  for (size_t i = 0; i < len; ++i) {
    ctx.buf[ctx.buf_len++] = data[i];
    if (ctx.buf_len == 64) {
      sha1_compress(ctx, ctx.buf);
      ctx.buf_len = 0;
    }
  }
}

static void sha1_final(SHA1_CTX& ctx, uint8_t digest[20]) {
  ctx.buf[ctx.buf_len++] = 0x80;
  if (ctx.buf_len > 56) {
    while (ctx.buf_len < 64) ctx.buf[ctx.buf_len++] = 0;
    sha1_compress(ctx, ctx.buf);
    ctx.buf_len = 0;
  }
  while (ctx.buf_len < 56) ctx.buf[ctx.buf_len++] = 0;
  for (int i = 7; i >= 0; --i)
    ctx.buf[ctx.buf_len++] = (ctx.count >> (i * 8)) & 0xFF;
  sha1_compress(ctx, ctx.buf);

  for (int i = 0; i < 5; ++i) {
    digest[i * 4] = (ctx.state[i] >> 24) & 0xFF;
    digest[i * 4 + 1] = (ctx.state[i] >> 16) & 0xFF;
    digest[i * 4 + 2] = (ctx.state[i] >> 8) & 0xFF;
    digest[i * 4 + 3] = (ctx.state[i]) & 0xFF;
  }
}

static std::array<uint8_t, 20> sha1(const std::string& s) {
  SHA1_CTX ctx;
  sha1_init(ctx);
  sha1_update(ctx, reinterpret_cast<const uint8_t*>(s.data()), s.size());
  std::array<uint8_t, 20> digest{};
  sha1_final(ctx, digest.data());
  return digest;
}

// ======================
// Base64
// ======================

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const uint8_t* data, size_t len) {
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t b = (uint32_t(data[i]) << 16) |
                 (i + 1 < len ? uint32_t(data[i + 1]) << 8 : 0) |
                 (i + 2 < len ? uint32_t(data[i + 2]) : 0);
    out += B64_TABLE[(b >> 18) & 0x3F];
    out += B64_TABLE[(b >> 12) & 0x3F];
    out += (i + 1 < len) ? B64_TABLE[(b >> 6) & 0x3F] : '=';
    out += (i + 2 < len) ? B64_TABLE[(b) & 0x3F] : '=';
  }
  return out;
}

// Convenience wrappers for strings/vectors
static std::string base64_encode(const std::string& s) {
  return base64_encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
static std::string base64_encode(const std::vector<uint8_t>& v) {
  return base64_encode(v.data(), v.size());
}

// ======================
// Helper functions
// ======================

// Masking / unmasking (XOR) — RFC 6455, section 5.3
static std::vector<uint8_t> apply_mask(const std::vector<uint8_t>& data,
                                       const uint8_t mask[4]) {
  std::vector<uint8_t> out(data.size());
  for (size_t i = 0; i < data.size(); ++i) out[i] = data[i] ^ mask[i % 4];
  return out;
}

// Computes Sec-WebSocket-Accept from Sec-WebSocket-Key (RFC 6455, section 1.3)
static std::string compute_accept_key(const std::string& key) {
  auto digest = sha1(key + WS_GUID);
  return base64_encode(digest.data(), 20);
}

// Generates a cryptographically random Sec-WebSocket-Key
static std::string generate_key() {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(0, 255);
  std::vector<uint8_t> bytes(16);
  for (auto& b : bytes) b = static_cast<uint8_t>(dist(gen));
  return base64_encode(bytes);
}

// Generates 4 random bytes for the masking key
static void random_bytes(uint8_t* buf, size_t n) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(0, 255);
  for (size_t i = 0; i < n; ++i) buf[i] = static_cast<uint8_t>(dist(gen));
}

// Convert string to lowercase
static std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return s;
}

// ======================
// Network primitives
// ======================

// Reads exactly n bytes from the socket
static bool recv_exactly(int fd, void* buf, size_t n) {
  size_t got = 0;
  auto* ptr = static_cast<uint8_t*>(buf);
  while (got < n) {
    ssize_t r = recv(fd, ptr + got, n - got, MSG_WAITALL);
    if (r <= 0) return false;
    got += r;
  }
  return true;
}

// Reads HTTP headers up to \r\n\r\n
static std::string read_http_headers(int fd) {
  std::string result;
  result.reserve(512);
  while (true) {
    char c;
    ssize_t r = recv(fd, &c, 1, 0);
    if (r <= 0)
      throw std::runtime_error("Connection broken while reading headers");
    result += c;
    if (result.size() >= 4 &&
        result.compare(result.size() - 4, 4, "\r\n\r\n") == 0)
      break;
    if (result.size() > 16 * 1024)
      throw std::runtime_error("Headers too large");
  }
  return result;
}

// Sends all bytes to the socket
static bool send_all(int fd, const uint8_t* data, size_t n, std::mutex& mu) {
  std::lock_guard<std::mutex> lock(mu);
  size_t sent = 0;
  while (sent < n) {
    ssize_t s = send(fd, data + sent, n - sent, MSG_NOSIGNAL);
    if (s <= 0) return false;
    sent += s;
  }
  return true;
}

static bool send_all(int fd, const std::vector<uint8_t>& v, std::mutex& mu) {
  return send_all(fd, v.data(), v.size(), mu);
}

// ======================
// Frame builder (RFC 6455, section 5.2)
// ======================

static std::vector<uint8_t> build_frame(const std::vector<uint8_t>& payload,
                                        uint8_t opcode, bool mask = false) {
  bool is_control =
      (opcode == OP_CLOSE || opcode == OP_PING || opcode == OP_PONG);
  if (is_control && payload.size() > 125)
    throw std::invalid_argument("Control frame payload > 125 bytes");
  if (payload.size() > MAX_PAYLOAD)
    throw std::invalid_argument("Payload too large");

  std::vector<uint8_t> frame;
  frame.reserve(payload.size() + 14);

  frame.push_back(0x80 | opcode);  // FIN=1, RSV=0, opcode

  size_t len = payload.size();
  uint8_t mask_bit = mask ? 0x80 : 0x00;
  if (len <= 125) {
    frame.push_back(mask_bit | uint8_t(len));
  } else if (len <= 65535) {
    frame.push_back(mask_bit | 126);
    frame.push_back((len >> 8) & 0xFF);
    frame.push_back(len & 0xFF);
  } else {
    frame.push_back(mask_bit | 127);
    for (int i = 7; i >= 0; --i) frame.push_back((len >> (i * 8)) & 0xFF);
  }

  if (mask) {
    uint8_t mk[4];
    random_bytes(mk, 4);
    frame.insert(frame.end(), mk, mk + 4);
    auto masked = apply_mask(payload, mk);
    frame.insert(frame.end(), masked.begin(), masked.end());
  } else {
    frame.insert(frame.end(), payload.begin(), payload.end());
  }

  return frame;
}

// Convenience overload for text strings
static std::vector<uint8_t> build_frame(const std::string& text, uint8_t opcode,
                                        bool mask = false) {
  std::vector<uint8_t> v(text.begin(), text.end());
  return build_frame(v, opcode, mask);
}

// ======================
// Frame parser (RFC 6455, section 5.2)
// ======================

struct Frame {
  uint8_t opcode;
  bool fin;
  bool masked;
  std::vector<uint8_t> payload;
};

// Exception hierarchy for protocol errors
struct ProtocolError : std::runtime_error {
  uint16_t close_code;
  ProtocolError(const std::string& msg, uint16_t code = CLOSE_PROTO_ERROR)
      : std::runtime_error(msg), close_code(code) {}
};
struct ConnectionClosed : std::runtime_error {
  using std::runtime_error::runtime_error;
};
struct FrameTooBig : ProtocolError {
  FrameTooBig() : ProtocolError("Frame too large", CLOSE_TOO_BIG) {}
};

static Frame parse_frame(int fd) {
  // Read 2-byte frame header
  uint8_t header[2];
  if (!recv_exactly(fd, header, 2))
    throw ConnectionClosed("Connection broken while reading frame header");

  bool fin = (header[0] & 0x80) != 0;
  uint8_t rsv = (header[0] & 0x70);
  uint8_t opcode = (header[0] & 0x0F);
  bool masked = (header[1] & 0x80) != 0;
  uint8_t len_b = (header[1] & 0x7F);

  // RSV bits must be zero without a negotiated extension (RFC 6455,
  // section 5.2)
  if (rsv != 0)
    throw ProtocolError("Non-zero RSV bits without a negotiated extension");

  // Parse payload length
  uint64_t payload_len = 0;
  if (len_b == 126) {
    uint8_t ext[2];
    if (!recv_exactly(fd, ext, 2))
      throw ConnectionClosed("Connection broken while reading length");
    payload_len = (uint64_t(ext[0]) << 8) | ext[1];
    if (payload_len <= 125)
      throw ProtocolError(
          "Non-minimal length encoding (126 used instead of 1 byte)");
  } else if (len_b == 127) {
    uint8_t ext[8];
    if (!recv_exactly(fd, ext, 8))
      throw ConnectionClosed("Connection broken while reading length");
    for (int i = 0; i < 8; ++i) payload_len = (payload_len << 8) | ext[i];
    if (payload_len >> 63)
      throw ProtocolError(
          "Most-significant bit of 64-bit length field is non-zero");
    if (payload_len <= 65535)
      throw ProtocolError(
          "Non-minimal length encoding (127 used instead of 2 bytes)");
  } else {
    payload_len = len_b;
  }

  if (payload_len > MAX_PAYLOAD) throw FrameTooBig();

  // Validate control frame constraints (RFC 6455, section 5.5)
  bool is_ctrl = (opcode == OP_CLOSE || opcode == OP_PING || opcode == OP_PONG);
  if (is_ctrl) {
    if (!fin) throw ProtocolError("Control frame is fragmented (FIN=0)");
    if (payload_len > 125)
      throw ProtocolError("Control frame payload > 125 bytes");
  }

  // Masking key
  uint8_t mk[4] = {};
  if (masked && !recv_exactly(fd, mk, 4))
    throw ConnectionClosed("Connection broken while reading masking key");

  // Payload
  std::vector<uint8_t> payload(payload_len);
  if (payload_len > 0 && !recv_exactly(fd, payload.data(), payload_len))
    throw ConnectionClosed("Connection broken while reading payload");

  if (masked) payload = apply_mask(payload, mk);

  return {opcode, fin, masked, std::move(payload)};
}

// ======================
// Control frames
// ======================

static void send_ping(int fd, std::mutex& mu,
                      const std::vector<uint8_t>& payload = {},
                      bool mask = false) {
  send_all(fd, build_frame(payload, OP_PING, mask), mu);
}

static void send_pong(int fd, std::mutex& mu,
                      const std::vector<uint8_t>& payload = {},
                      bool mask = false) {
  send_all(fd, build_frame(payload, OP_PONG, mask), mu);
}

static void send_close(int fd, std::mutex& mu, uint16_t code = CLOSE_NORMAL,
                       const std::string& reason = "", bool mask = false) {
  if (code == 1005 || code == 1006 || code == 1015)
    throw std::invalid_argument("Reserved close code");
  std::vector<uint8_t> payload;
  payload.push_back((code >> 8) & 0xFF);
  payload.push_back(code & 0xFF);
  for (char c : reason) payload.push_back(uint8_t(c));
  send_all(fd, build_frame(payload, OP_CLOSE, mask), mu);
}

static bool validate_close_code(uint16_t code) {
  if (code < 1000 || code > 4999) return false;
  if (code == 1004 || code == 1005 || code == 1006 || code == 1015)
    return false;
  if (code >= 1016 && code <= 2999) return false;
  return true;
}

// Validates that a byte sequence is valid UTF-8
static bool is_valid_utf8(const uint8_t* data, size_t len) {
  size_t i = 0;
  while (i < len) {
    uint8_t b = data[i++];
    int extra = 0;
    if ((b & 0x80) == 0x00)
      extra = 0;
    else if ((b & 0xE0) == 0xC0)
      extra = 1;
    else if ((b & 0xF0) == 0xE0)
      extra = 2;
    else if ((b & 0xF8) == 0xF0)
      extra = 3;
    else
      return false;
    for (int j = 0; j < extra; ++j) {
      if (i >= len || (data[i++] & 0xC0) != 0x80) return false;
    }
  }
  return true;
}

static void handle_close(int fd, std::mutex& mu,
                         const std::vector<uint8_t>& payload, bool mask,
                         const std::string& side) {
  if (payload.empty()) {
    std::vector<uint8_t> empty;
    send_all(fd, build_frame(empty, OP_CLOSE, mask), mu);
    return;
  }
  if (payload.size() == 1) {
    send_close(fd, mu, CLOSE_PROTO_ERROR, "", mask);
    return;
  }
  uint16_t code = (uint16_t(payload[0]) << 8) | payload[1];
  if (!validate_close_code(code)) {
    ws_log(side, "!", "PROTO", "Invalid close code: " + std::to_string(code));
    send_close(fd, mu, CLOSE_PROTO_ERROR, "", mask);
    return;
  }
  if (payload.size() > 2) {
    if (!is_valid_utf8(payload.data() + 2, payload.size() - 2)) {
      send_close(fd, mu, CLOSE_INVALID_UTF8, "", mask);
      return;
    }
  }
  send_close(fd, mu, code, "", mask);
}

// ======================
// Frame dispatcher (RFC 6455, section 5)
// ======================

// Result of processing a single frame
struct DispatchResult {
  bool should_close = false;
  bool has_message = false;
  std::string text_message;
  std::vector<uint8_t> binary_message;
  bool is_text = true;
};

static std::string opcode_name(uint8_t op) {
  switch (op) {
    case OP_CONTINUATION:
      return "CONT";
    case OP_TEXT:
      return "TEXT";
    case OP_BINARY:
      return "BIN";
    case OP_CLOSE:
      return "CLOSE";
    case OP_PING:
      return "PING";
    case OP_PONG:
      return "PONG";
  }
  std::ostringstream oss;
  oss << "0x" << std::hex << int(op);
  return oss.str();
}

struct FragmentState {
  std::vector<uint8_t> fragments;  // accumulated fragment data
  uint8_t first_opcode = 0;
  bool in_progress = false;
};

static DispatchResult dispatch_frame(const Frame& frame, int fd, std::mutex& mu,
                                     const std::string& side, bool is_client,
                                     bool close_sent, FragmentState& frag) {
  bool out_mask = is_client;

  // Log the incoming frame
  {
    std::string payload_preview;
    for (size_t i = 0; i < std::min(frame.payload.size(), size_t(20)); ++i) {
      uint8_t b = frame.payload[i];
      if (b >= 32 && b < 127)
        payload_preview += char(b);
      else {
        char tmp[8];
        snprintf(tmp, sizeof(tmp), "\\x%02X", b);
        payload_preview += tmp;
      }
    }
    if (frame.payload.size() > 20) payload_preview += "...";
    ws_log(side, "<-", "FRAME",
           "opcode=" + opcode_name(frame.opcode) +
               " fin=" + std::to_string(int(frame.fin)) +
               " masked=" + std::to_string(int(frame.masked)) +
               " len=" + std::to_string(frame.payload.size()) + " payload=\"" +
               payload_preview + "\"");
  }

  // Validate masking bit (RFC 6455, section 5.3)
  bool expected_masked = !is_client;
  if (frame.masked != expected_masked) {
    ws_log(side, "!", "PROTO",
           "Masking violation: masked=" + std::to_string(frame.masked) +
               " expected=" + std::to_string(expected_masked));
    send_close(fd, mu, CLOSE_PROTO_ERROR, "", out_mask);
    return {true};
  }

  // Control frames (RFC 6455, section 5.5)
  if (frame.opcode == OP_PING) {
    ws_log(side, "->", "FRAME",
           "opcode=PONG len=" + std::to_string(frame.payload.size()));
    send_pong(fd, mu, frame.payload, out_mask);
    return {false};
  }
  if (frame.opcode == OP_PONG) {
    ws_log(side, "·", "FRAME", "opcode=PONG received");
    return {false};
  }
  if (frame.opcode == OP_CLOSE) {
    if (!close_sent) {
      ws_log(side, "->", "FRAME", "opcode=CLOSE (reply)");
      handle_close(fd, mu, frame.payload, out_mask, side);
    } else {
      ws_log(side, "·", "FRAME", "opcode=CLOSE (no reply sent)");
    }
    return {true};
  }

  // Data frames (RFC 6455, section 5.4 — Fragmentation)
  if (frame.opcode == OP_TEXT || frame.opcode == OP_BINARY) {
    if (frag.in_progress) {
      // New data frame received while fragmented sequence is incomplete
      send_close(fd, mu, CLOSE_PROTO_ERROR, "", out_mask);
      return {true};
    }
    frag.in_progress = true;
    frag.first_opcode = frame.opcode;
    frag.fragments = frame.payload;
  } else if (frame.opcode == OP_CONTINUATION) {
    if (!frag.in_progress) {
      send_close(fd, mu, CLOSE_PROTO_ERROR, "", out_mask);
      return {true};
    }
    frag.fragments.insert(frag.fragments.end(), frame.payload.begin(),
                          frame.payload.end());
  } else {
    ws_log(side, "!", "PROTO",
           "Unknown opcode 0x" +
               (std::ostringstream() << std::hex << int(frame.opcode)).str());
    send_close(fd, mu, CLOSE_PROTO_ERROR, "", out_mask);
    return {true};
  }

  if (!frame.fin) return {false};  // Wait for next fragment

  // Assemble the complete message
  if (frag.fragments.size() > MAX_PAYLOAD) {
    send_close(fd, mu, CLOSE_TOO_BIG, "", out_mask);
    frag = {};
    return {true};
  }

  DispatchResult res;
  res.has_message = true;
  res.is_text = (frag.first_opcode == OP_TEXT);
  frag.in_progress = false;

  if (res.is_text) {
    // UTF-8 validation (RFC 6455, section 5.6)
    if (!is_valid_utf8(frag.fragments.data(), frag.fragments.size())) {
      ws_log(side, "!", "PROTO",
             "Invalid UTF-8 in text frame, closing with code 1007");
      send_close(fd, mu, CLOSE_INVALID_UTF8, "", out_mask);
      frag = {};
      return {true};
    }
    res.text_message.assign(
        reinterpret_cast<const char*>(frag.fragments.data()),
        frag.fragments.size());
  } else {
    res.binary_message = std::move(frag.fragments);
  }
  frag.fragments.clear();
  return res;
}

// ======================
// SERVER (RFC 6455, section 4.2)
// ======================

// Parses a header dictionary from a raw HTTP request/response string
static std::unordered_map<std::string, std::string> extract_headers(
    const std::string& raw, std::string& first_line) {
  std::unordered_map<std::string, std::string> headers;
  std::istringstream ss(raw);
  std::getline(ss, first_line);
  // Strip trailing \r
  if (!first_line.empty() && first_line.back() == '\r') first_line.pop_back();

  std::string line;
  while (std::getline(ss, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) break;
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string k = to_lower(line.substr(0, colon));
    std::string v = line.substr(colon + 1);
    // Trim leading whitespace
    while (!v.empty() && v.front() == ' ') v.erase(v.begin());
    headers[k] = v;
  }
  return headers;
}

// Validates the HTTP Upgrade request (RFC 6455, section 4.2.1)
static std::string validate_handshake(
    const std::string& request_line,
    const std::unordered_map<std::string, std::string>& headers) {
  // Parse request line: METHOD PATH VERSION
  std::istringstream ss(request_line);
  std::string method, path, version;
  ss >> method >> path >> version;
  if (method != "GET") return "Method must be GET";
  if (version != "HTTP/1.1") return "HTTP/1.1 required";

  auto get = [&](const std::string& k) -> std::string {
    auto it = headers.find(k);
    return it != headers.end() ? it->second : "";
  };

  if (to_lower(get("upgrade")) != "websocket")
    return "Missing Upgrade: websocket header";
  if (get("connection").find("pgrade") == std::string::npos)
    return "Missing Connection: Upgrade header";
  if (get("sec-websocket-version") != "13")
    return "Invalid Sec-WebSocket-Version value";
  if (get("sec-websocket-key").empty())
    return "Missing Sec-WebSocket-Key header";
  return "";
}

// Performs the server-side WebSocket handshake
static bool perform_server_handshake(int fd, const std::string& side) {
  std::string raw;
  try {
    raw = read_http_headers(fd);
  } catch (const std::exception& e) {
    ws_log(side, "!", "ERROR", e.what());
    return false;
  }
  ws_log(side, "<-", "HTTP",
         "Request received (" + std::to_string(raw.size()) + " bytes)");

  std::string first_line;
  auto headers = extract_headers(raw, first_line);

  auto bad_request = [&](const std::string& reason) {
    ws_log(side, "->", "HTTP", "400 Bad Request: " + reason);
    std::string resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
    send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
  };

  std::string err = validate_handshake(first_line, headers);
  if (!err.empty()) {
    bad_request(err);
    return false;
  }

  std::string ws_key = headers["sec-websocket-key"];
  std::string accept = compute_accept_key(ws_key);

  ws_log(side, "·", "HAND", "Sec-WebSocket-Key=" + ws_key);
  ws_log(side, "·", "HAND", "Sec-WebSocket-Accept=" + accept);

  std::string resp =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: " +
      accept +
      "\r\n"
      "\r\n";
  if (send(fd, resp.data(), resp.size(), MSG_NOSIGNAL) < 0) return false;
  ws_log(side, "->", "HTTP", "101 Switching Protocols — handshake complete");
  ws_log(side, "·", "STATE", "OPEN");
  return true;
}

// Periodically sends messages from the server
static void server_ticker(int fd, std::mutex& mu, const std::string& side,
                          std::atomic<bool>& running) {
  int n = 0;
  while (running) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    if (!running) break;
    ++n;
    std::string msg = "message from SERVER #" + std::to_string(n);
    ws_log(side, "->", "APP", msg);
    ws_log(side, "->", "FRAME",
           "opcode=TEXT len=" + std::to_string(msg.size()));
    if (!send_all(fd, build_frame(msg, OP_TEXT, false), mu)) break;
  }
}

// Main message loop for a single server connection
static void server_handle(int client_fd) {
  const std::string side = "SERVER";

  if (!perform_server_handshake(client_fd, side)) {
    close(client_fd);
    return;
  }

  std::mutex write_mu;
  std::atomic<bool> running{true};
  FragmentState frag{};

  // Ticker runs in a dedicated thread
  std::thread ticker(
      [&]() { server_ticker(client_fd, write_mu, side, running); });

  // Main read loop
  try {
    while (true) {
      Frame frame = parse_frame(client_fd);
      auto res =
          dispatch_frame(frame, client_fd, write_mu, side, /*is_client=*/false,
                         /*close_sent=*/false, frag);
      if (res.has_message) {
        if (res.is_text)
          ws_log(side, "<-", "APP", "\"" + res.text_message + "\"");
        else
          ws_log(side, "<-", "APP",
                 "[binary " + std::to_string(res.binary_message.size()) +
                     " bytes]");
      }
      if (res.should_close) {
        ws_log(side, "·", "STATE", "CLOSING -> CLOSED");
        break;
      }
    }
  } catch (const ConnectionClosed& e) {
    ws_log(side, "!", "TCP",
           "Connection dropped (code 1006): " + std::string(e.what()));
  } catch (const ProtocolError& e) {
    ws_log(side, "!", "PROTO", e.what());
    try {
      send_close(client_fd, write_mu, e.close_code, "", false);
    } catch (...) {
    }
  } catch (const std::exception& e) {
    ws_log(side, "!", "ERROR", e.what());
  }

  running = false;
  ticker.join();
  close(client_fd);
  ws_log(side, "·", "STATE", "CLOSED");
  ws_log(side, "·", "TCP", "TCP connection closed");
}

static void run_server() {
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("socket");
    exit(1);
  }

  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(WS_PORT);
  inet_pton(AF_INET, WS_HOST, &addr.sin_addr);

  if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("bind");
    exit(1);
  }
  if (listen(server_fd, 5) < 0) {
    perror("listen");
    exit(1);
  }

  ws_log(
      "SERVER", "·", "TCP",
      std::string("Listening on ") + WS_HOST + ":" + std::to_string(WS_PORT));

  while (true) {
    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    int cfd = accept(server_fd, (sockaddr*)&peer, &peer_len);
    if (cfd < 0) break;

    char peer_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer.sin_addr, peer_str, sizeof(peer_str));
    ws_log("SERVER", "·", "TCP",
           "New connection from " + std::string(peer_str) + ":" +
               std::to_string(ntohs(peer.sin_port)));

    // Handle the connection in a dedicated thread
    std::thread([cfd]() { server_handle(cfd); }).detach();
  }
  close(server_fd);
}

// ======================
// CLIENT (RFC 6455, section 4.1)
// ======================

// Validates the server's handshake response
static std::string validate_server_response(
    const std::string& status_line,
    const std::unordered_map<std::string, std::string>& headers,
    const std::string& key) {
  if (status_line.find("101 Switching Protocols") == std::string::npos)
    return "Expected status 101 Switching Protocols, got: " + status_line;

  auto get = [&](const std::string& k) {
    auto it = headers.find(k);
    return it != headers.end() ? it->second : std::string{};
  };

  if (to_lower(get("upgrade")) != "websocket")
    return "Invalid Upgrade header in server response";
  if (get("connection").find("pgrade") == std::string::npos)
    return "Invalid Connection header in server response";

  std::string expected = compute_accept_key(key);
  std::string actual = get("sec-websocket-accept");
  if (actual != expected)
    return "Invalid Sec-WebSocket-Accept: " + actual + " != " + expected;

  return "";
}

static bool perform_client_handshake(int fd, const std::string& side) {
  std::string key = generate_key();
  ws_log(side, "·", "HAND", "Sec-WebSocket-Key=" + key);

  std::string req =
      "GET / HTTP/1.1\r\n"
      "Host: " +
      std::string(WS_HOST) + ":" + std::to_string(WS_PORT) +
      "\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: " +
      key +
      "\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "\r\n";

  if (send(fd, req.data(), req.size(), MSG_NOSIGNAL) < 0) return false;
  ws_log(side, "->", "HTTP", "GET / HTTP/1.1 (handshake request)");

  std::string raw = read_http_headers(fd);
  ws_log(side, "<-", "HTTP",
         "Response received (" + std::to_string(raw.size()) + " bytes)");

  std::string status_line;
  auto headers = extract_headers(raw, status_line);

  std::string err = validate_server_response(status_line, headers, key);
  if (!err.empty()) {
    ws_log(side, "!", "ERROR", err);
    return false;
  }

  ws_log(side, "·", "HAND",
         "Sec-WebSocket-Accept verified: " + compute_accept_key(key));
  ws_log(side, "·", "STATE", "OPEN");
  return true;
}

// Periodically sends messages and initiates connection close
static void client_sender(int fd, std::mutex& mu, const std::string& side,
                          std::atomic<bool>& close_sent) {
  int n = 0;
  try {
    while (true) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      ++n;
      std::string msg = "message from CLIENT #" + std::to_string(n);
      ws_log(side, "->", "APP", msg);
      ws_log(side, "->", "FRAME",
             "opcode=TEXT len=" + std::to_string(msg.size()) + " MASKED=1");
      if (!send_all(fd, build_frame(msg, OP_TEXT, true), mu)) break;

      if (n >= 5) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        ws_log(side, "->", "APP", "Initiating connection close");

        std::vector<uint8_t> close_payload;
        close_payload.push_back((CLOSE_NORMAL >> 8) & 0xFF);
        close_payload.push_back(CLOSE_NORMAL & 0xFF);
        std::string reason = "done";
        for (char c : reason) close_payload.push_back(uint8_t(c));

        send_all(fd, build_frame(close_payload, OP_CLOSE, true), mu);
        close_sent = true;
        break;
      }
    }
  } catch (...) {
  }
}

static void run_client() {
  const std::string side = "CLIENT";

  // Brief delay to give the server time to start up
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(WS_PORT);
  inet_pton(AF_INET, WS_HOST, &addr.sin_addr);

  // Retry connection until the server is ready
  for (int attempt = 0; attempt < 20; ++attempt) {
    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) == 0) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (attempt == 19) {
      ws_log(side, "!", "TCP", "Failed to connect");
      close(fd);
      return;
    }
  }
  ws_log(
      side, "·", "TCP",
      std::string("Connected to ") + WS_HOST + ":" + std::to_string(WS_PORT));

  if (!perform_client_handshake(fd, side)) {
    close(fd);
    return;
  }

  std::mutex write_mu;
  std::atomic<bool> close_sent{false};
  FragmentState frag{};

  // Sender runs in a dedicated thread
  std::thread sender([&]() { client_sender(fd, write_mu, side, close_sent); });

  // Main read loop
  try {
    while (true) {
      Frame frame = parse_frame(fd);
      auto res = dispatch_frame(frame, fd, write_mu, side, /*is_client=*/true,
                                close_sent.load(), frag);
      if (res.has_message) {
        if (res.is_text)
          ws_log(side, "<-", "APP", "\"" + res.text_message + "\"");
        else
          ws_log(side, "<-", "APP",
                 "[binary " + std::to_string(res.binary_message.size()) +
                     " bytes]");
      }
      if (res.should_close) {
        ws_log(side, "·", "STATE", "CLOSING");
        break;
      }
    }
  } catch (const ConnectionClosed& e) {
    ws_log(side, "!", "TCP",
           "Connection dropped (code 1006): " + std::string(e.what()));
  } catch (const ProtocolError& e) {
    ws_log(side, "!", "PROTO", e.what());
    try {
      send_close(fd, write_mu, e.close_code, "", true);
    } catch (...) {
    }
  } catch (const std::exception& e) {
    ws_log(side, "!", "ERROR", e.what());
  }

  sender.join();
  close(fd);
  ws_log(side, "·", "STATE", "CLOSED");
  ws_log(side, "·", "TCP", "TCP connection closed");
}

// ======================
// Entry point
// ======================

int main() {
  // Ignore SIGPIPE — writing to a closed socket returns EPIPE instead of
  // killing the process
  signal(SIGPIPE, SIG_IGN);

  pid_t server_pid = fork();
  if (server_pid < 0) {
    perror("fork");
    return 1;
  }

  if (server_pid == 0) {
    // Child process — server
    run_server();
    return 0;
  }

  // Parent process — client
  run_client();

  // Shut down the server
  kill(server_pid, SIGTERM);
  waitpid(server_pid, nullptr, 0);
  return 0;
}
