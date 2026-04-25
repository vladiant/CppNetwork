#pragma once

#include <atomic>
#include <string>

namespace appsniff {

struct SnifferOptions {
  std::string interface;   // empty = auto-pick
  std::string bpf_filter;  // optional extra BPF
  int snaplen = 65535;
  int timeout_ms = 100;
  bool promiscuous = true;
};

class Sniffer {
 public:
  explicit Sniffer(SnifferOptions opts);
  ~Sniffer();

  Sniffer(const Sniffer&) = delete;
  Sniffer& operator=(const Sniffer&) = delete;

  void run();  // blocks until stop() or error
  void stop();

 private:
  struct Impl;
  Impl* impl_;
  std::atomic<bool> running_{false};
};

}  // namespace appsniff
