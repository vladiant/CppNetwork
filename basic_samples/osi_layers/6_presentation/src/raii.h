#pragma once

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <unistd.h>

#include <memory>

namespace presentation {

// Generic deleter dispatcher for OpenSSL types.
template <auto Fn>
struct OsslDeleter {
  template <typename T>
  void operator()(T* p) const noexcept {
    if (p) Fn(p);
  }
};

using SslCtxPtr = std::unique_ptr<SSL_CTX, OsslDeleter<&SSL_CTX_free>>;
using SslPtr = std::unique_ptr<SSL, OsslDeleter<&SSL_free>>;
using X509Ptr = std::unique_ptr<X509, OsslDeleter<&X509_free>>;
using EvpPKeyPtr = std::unique_ptr<EVP_PKEY, OsslDeleter<&EVP_PKEY_free>>;

// RAII wrapper for a POSIX file descriptor.
class FileDescriptor {
 public:
  FileDescriptor() noexcept = default;
  explicit FileDescriptor(int fd) noexcept : fd_{fd} {}
  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;
  FileDescriptor(FileDescriptor&& o) noexcept : fd_{o.fd_} { o.fd_ = -1; }
  FileDescriptor& operator=(FileDescriptor&& o) noexcept {
    if (this != &o) {
      reset();
      fd_ = o.fd_;
      o.fd_ = -1;
    }
    return *this;
  }
  ~FileDescriptor() { reset(); }

  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
  explicit operator bool() const noexcept { return valid(); }

  void reset(int fd = -1) noexcept {
    if (fd_ >= 0) ::close(fd_);
    fd_ = fd;
  }
  [[nodiscard]] int release() noexcept {
    int f = fd_;
    fd_ = -1;
    return f;
  }

 private:
  int fd_{-1};
};

}  // namespace presentation
