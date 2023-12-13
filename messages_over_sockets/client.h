#include <thread>

#include "common.h"

class Client {
 public:
  Client(const char* hostname, const char* port)
      : remote_hostname_(hostname), remote_port_(port) {}

  Client(const Client& other) = delete;
  Client& operator=(const Client& other) = delete;

  ~Client() { Disconnect(); }

 public:
  int Start() noexcept;

  void Disconnect() noexcept;

 private:
  /* Creates new `addrinfo` object and fills it with connection information.
   * @return `nullptr` on error, pointer to `addrinfo` object on success.
   */
  addrinfo* ResolveConnectionAddress() noexcept;

  // @return `-1` on error, valid socket on success.
  SOCKET CreateConnectionSocket(addrinfo* conn_addr) noexcept;

  int SendMessage(const std::string& message) noexcept;

  int ReceiveMessage(char* writable_buff) noexcept;

  // Prints the input prompt and flushes stdout afterwards.
  void PrintInputPrompt() const noexcept;

  /* Handles user input and message-sending process.
   * @return `-1` on error, `0` on successful exit.
   */
  int InputHandler();

  /* Main client application loop. Handles incoming data and accepts user input.
   * @return `-1` on error, `0` on successful exit.
   */
  int HandleConnection() noexcept;

 private:
  const std::string remote_hostname_, remote_port_;

  SOCKET connection_socket_;
};