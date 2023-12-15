#include <unordered_map>

#include "common.h"

#define BACKLOG 10

struct ConnectionInfo {
  bool success;
  std::string address;
  std::string port;

  std::string ToString() const noexcept {
    using namespace std::string_literals;  // String optimization

    return address + ":"s + port;
  }
};

inline static ConnectionInfo GetConnectionInfo(sockaddr_storage* addr) {
  // Create required structures for getpeername() call
  sockaddr_in* conn_addr = reinterpret_cast<sockaddr_in*>(
      addr);  // informational structure for IPv4 connections

  ConnectionInfo ret_conn;
  ret_conn.success = false;

  char ip_addr[INET_ADDRSTRLEN];
  // Retrieve the IP address from the connection and write it to ip_addr string
  // buffer.
  inet_ntop(AF_INET, &conn_addr->sin_addr, ip_addr, INET_ADDRSTRLEN);

  ret_conn.address = std::string(ip_addr);
  ret_conn.port = std::to_string(conn_addr->sin_port);
  ret_conn.success = true;

  return ret_conn;
}

class Server {
 public:
  Server(const char* hostname, const char* port)
      : hostname_(hostname), port_(port) {}

  // Prohibit any copying.
  Server(const Server& other) = delete;
  Server& operator=(const Server& other) = delete;

  ~Server();

 public:
  int Start() noexcept;

  void Shutdown() noexcept;

 private:
  /* Creates a new configured server socket from `bind_address`.
   * @return valid socket on success, invalid one on error
   */
  SOCKET CreateServerSocket(addrinfo* bind_address) noexcept;

  /* Resolves server local address based on the `hostname_` and `port_`
   * variables.
   * @return `nullptr` on error, `addrinfo` pointer on success.
   */
  addrinfo* GetServerLocalAddress() noexcept;

  /* Sets necessary options for `serv_socket`.
   * @returns `-1` on error, `0` on success.
   */
  int ConfigureServerSocket(SOCKET serv_socket) noexcept;

  /* Send `message` to `receipient_socketfd`.
   * @return `-1` on error, sent bytes on success.
   */
  int SendMessage(SOCKET receipient_socketfd,
                  const std::string& message) noexcept;

  /* Send `message` from `conn_from` to all connected clients.
   * @return `-1` on error, `0` on success.
   */
  int BroadcastMessage(const std::string& message,
                       const ConnectionInfo& conn_from) noexcept;

  /* Receive data from `sender_socketfd` and write it to `writable_buffer`.
   * @return `-1` on error, `0` on client disconnect, received bytes on success.
   */
  int ReceiveMessage(SOCKET sender_socketfd, char* writable_buffer) noexcept;

  /* Tries to accept a new incoming connection to `server_socket_`.
   * @return `-1` on error, `0` on success.
   */
  int AcceptConnection() noexcept;

  void DisconnectClient(SOCKET sockfd) noexcept;

  /* Server's main loop. Handles incoming data and accepts new connections.
   * @return `-1` on error, `0` on successful shutdown.
   */
  int HandleConnections() noexcept;

 private:
  const std::string hostname_, port_;

  SOCKET server_socket_;

  // Variables for select() system call.
  SOCKET max_socket_;
  fd_set sock_polling_set_;

  std::unordered_map<SOCKET, ConnectionInfo> connected_clients_;
};