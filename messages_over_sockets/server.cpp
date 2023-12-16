#include "server.h"

using namespace std::string_literals;  // String operations optimization

Server::~Server() { Shutdown(); }

int Server::Start() noexcept {
  addrinfo* server_addr_struct = GetServerLocalAddress();
  if (!server_addr_struct) {
    return -1;
  }

  server_socket_ = CreateServerSocket(server_addr_struct);
  if (!IS_VALID_SOCKET(server_socket_)) {
    return -1;
  }
  freeaddrinfo(
      server_addr_struct);  // Free the resources we won't need anymore.

  // Add the server socket to the socket polling list.
  FD_ZERO(&sock_polling_set_);
  FD_SET(server_socket_, &sock_polling_set_);
  max_socket_ = server_socket_;

  return HandleConnections();
}

void Server::Shutdown() noexcept {
  std::cerr << "[Info] Shutting down the server...\n"s;
  CLOSE_SOCKET(server_socket_);
  std::cerr << "[Info] Server is shut down." << std::endl;
}

SOCKET Server::CreateServerSocket(addrinfo* bind_address) noexcept {
  if (!bind_address) {
    std::cerr << "[Error] CreateServerSocket(): bind_address is NULL."s
              << std::endl;
    return -1;
  }

  // Create a new socket from the resolved address
  std::cerr << "[Debug] Creating server socket object.\n"s;
  SOCKET server_socket =
      socket(bind_address->ai_family, bind_address->ai_socktype,
             bind_address->ai_protocol);
  if (!IS_VALID_SOCKET(server_socket)) {
    std::cerr << "[Error] Failed to create server socket: socket(): "s
              << std::system_category().message(GET_SOCKET_ERRNO())
              << std::endl;
    return -1;
  }

  std::cerr << "[Debug] Binding socket to the resolved address."s << std::endl;
  if (bind(server_socket, bind_address->ai_addr, bind_address->ai_addrlen) ==
      -1) {
    std::cerr << "[Error] Failed to bind server socket to address "s
              << hostname_ << ":"s << port_ << " : bind(): "s
              << std::system_category().message(GET_SOCKET_ERRNO())
              << std::endl;
    return -1;
  }
  // Setting all necessary options for the server socket
  if (ConfigureServerSocket(server_socket) == -1) {
    return -1;
  }
  return server_socket;
}

int Server::ConfigureServerSocket(SOCKET serv_socket) noexcept {
#ifdef _WIN32
  char yes = 1;  // Setting variable
#else
  int yes = 1;
#endif
  std::cerr
      << "[Debug] Setting SO_REUSEADDR socket option to the server socket.\n"s;
  if (setsockopt(serv_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) ==
      -1) {
    std::cerr << "[Error] Failed to set socket options: setsockopt(): "s
              << std::system_category().message(GET_SOCKET_ERRNO())
              << std::endl;
    return -1;
  }

  std::cerr << "[Debug] Activating server listenning mode.\n"s;
  if (listen(serv_socket, BACKLOG) == -1) {
    std::cerr << "[Error] Failed to activate socket listenner: listen(): "s
              << std::system_category().message(GET_SOCKET_ERRNO())
              << std::endl;
    return -1;
  }
  std::cout << "[Info] Server is listenning for incoming connections at "s
            << hostname_ << ":"s << port_ << '\n';
  return 0;
}

addrinfo* Server::GetServerLocalAddress() noexcept {
  // Create needed data structures
  addrinfo hints, *bind_address;
  // Create a configuration structure for getting server's address structure
  memset(&hints, 0x00, sizeof(hints));
  hints.ai_family = AF_INET;  // Use IPv4
  hints.ai_socktype =
      SOCK_STREAM;  // Use TCP, SOCK_DGRAM for UDP, SOCK_RAW for IP, ICMP, RAW

  // Try to resolve server's local address and write it to bind_address variable
  std::cerr << "[Debug] Resolving server hostname.\n"s;
  if (getaddrinfo(hostname_.data(), port_.data(), &hints, &bind_address) != 0) {
    std::cerr
        << "[Error] Failed to resolve server's local address: getaddrinfo(): "s
        << std::system_category().message(GET_SOCKET_ERRNO()) << std::endl;
    return nullptr;
  }

  return bind_address;
}

int Server::AcceptConnection() noexcept {
  // Create new structures for storing data about connecting client.
  sockaddr_storage conn_addr;
  socklen_t conn_len = sizeof(conn_addr);

  SOCKET new_conn = accept(server_socket_,
                           reinterpret_cast<sockaddr*>(&conn_addr), &conn_len);
  ConnectionInfo new_conn_info = GetConnectionInfo(&conn_addr);
  if (!IS_VALID_SOCKET(new_conn)) {
    std::cerr << "[Error] Failed to accept new connection from "s
              << new_conn_info.ToString() << " : accept(): "s
              << std::system_category().message(GET_SOCKET_ERRNO())
              << std::endl;
    return -1;
  }

  std::cout << "[Info] New connection from "s << new_conn_info.ToString()
            << '\n';

  // Add the newly connected client to our server data structures.
  if (new_conn > max_socket_) {
    max_socket_ = new_conn;
  }
  FD_SET(new_conn, &sock_polling_set_);
  connected_clients_[new_conn] = new_conn_info;
  return 0;
}

void Server::DisconnectClient(SOCKET sockfd) noexcept {
  const ConnectionInfo& conn_info = connected_clients_.at(sockfd);
  std::cerr << "[Info] Client "s << conn_info.ToString()
            << " has been disconnected.\n"s;

  CLOSE_SOCKET(sockfd);
  connected_clients_.erase(sockfd);
  FD_CLR(sockfd, &sock_polling_set_);
}

int Server::HandleConnections() noexcept {
  while (true) {
    // Create a copy of the main polling set, since select() modifies fd_set
    // structure.
    fd_set polling_set_copy = sock_polling_set_;

    // See if there is any data available for reading.
    if (select(max_socket_ + 1, &polling_set_copy, NULL, NULL, NULL) < 0) {
      std::cerr
          << "[Error] Failed to fetch data on the server socket: select(): "s
          << std::system_category().message(GET_SOCKET_ERRNO()) << std::endl;
      return -1;
    }

    // Find the socket who sent the data.
    for (SOCKET sock = 1; sock <= max_socket_ + 1; ++sock) {
      if (FD_ISSET(
              sock,
              &polling_set_copy)) {  // the socket should be in the polling set.
        if (sock == server_socket_) {  // Received data on the listenning socket
                                       // == new connection
          if (AcceptConnection() ==
              -1) {  // Almost always, if a client fails to connect, the problem
                     // is related to the server.
            return -1;
          }
        } else {  // Regular client is sending us some data
          char msg_buffer[MAX_DATA_BUFFER_SIZE];
          memset(msg_buffer, 0x00, MAX_DATA_BUFFER_SIZE);

          int recv_bytes = ReceiveMessage(sock, msg_buffer);

          if (recv_bytes <= 0) {  // An error has occurred
            DisconnectClient(sock);
            continue;
          }
          std::string msg_str(msg_buffer);
          BroadcastMessage(msg_str, connected_clients_.at(sock));
        }
      }  // if (FD_ISSET)
    }    // for (SOCKET sock)
  }      // while (true)
  return 0;
}

int Server::SendMessage(SOCKET receipient_socketfd,
                        const std::string& message) noexcept {
  std::string assembled_msg = message;
  PrependMessageLength(assembled_msg);

  int total_bytes = assembled_msg.size();
  int sent_bytes = 0;
  int sent_n;  // temporary variable
  const ConnectionInfo& conn_info = connected_clients_.at(receipient_socketfd);

  // Try to sent all bytes.
  while (sent_bytes < total_bytes) {
    std::cerr << "[Info] Sending "s << total_bytes - sent_bytes << " bytes to "s
              << conn_info.ToString() << std::endl;
    sent_n = send(receipient_socketfd, assembled_msg.data() + sent_bytes,
                  total_bytes - sent_bytes, 0);
    if (sent_n == -1) {
      std::cerr << "[Error] Failed to send data to "s << conn_info.ToString()
                << " : send(): "s
                << std::system_category().message(GET_SOCKET_ERRNO())
                << std::endl;
      return sent_n;
    }
    sent_bytes += sent_n;
  }
  return sent_bytes;
}
int Server::BroadcastMessage(const std::string& message,
                             const ConnectionInfo& conn_from) noexcept {
  // Prepend the message with the address of the client who's sending it.
  std::string packet = conn_from.ToString() + " to ALL: "s + message;
  for (const auto& [sock, client_info] : connected_clients_) {
    if (SendMessage(sock, packet) == -1) {
      DisconnectClient(sock);
      return -1;
    }
  }
  return 0;
}

int Server::ReceiveMessage(SOCKET sender_socketfd,
                           char* writable_buffer) noexcept {
  if (!writable_buffer) {
    std::cerr << "[Error] ReceiveMessage(): writable_buffer is NULL."s
              << std::endl;
    return -1;
  }
  const ConnectionInfo& conn_info = connected_clients_.at(sender_socketfd);

  // first we need to get the length of the preceeding data chunk.
  char message_size_str[5];  // 4 + 1 null-character

  memset(message_size_str, 0x00, sizeof(message_size_str));
  message_size_str[4] = '\0';

  int recv_bytes =
      recv(sender_socketfd, message_size_str, sizeof(message_size_str) - 1, 0);
  if (recv_bytes <= 0) {
    if (recv_bytes < 0) {
      std::cerr << "[Error] Failed to receive message length from "s
                << conn_info.ToString() << " : recv(): "s
                << std::system_category().message(GET_SOCKET_ERRNO())
                << std::endl;
    }
    return recv_bytes;
  }
  std::cerr << "[Debug] "s << conn_info.ToString() << " (4 bytes): '"s
            << message_size_str << "'\n"s;
  // check if the received string is an actual number
  for (const char c : std::string(message_size_str)) {
    if (!std::isdigit(c)) {
      std::cerr << "[Warning] Client "s << conn_info.ToString()
                << " : Communication protocol violaition. (char '"s << c
                << "')\n"s;
      return -1;
    }
  }
  int packet_length = std::atoi(message_size_str);
  recv_bytes = recv(sender_socketfd, writable_buffer, packet_length, 0);
  if (recv_bytes <= 0) {
    if (recv_bytes < 0) {
      std::cerr << "[Error] Failed to receive message from "s
                << conn_info.ToString() << " : recv(): "s
                << std::system_category().message(GET_SOCKET_ERRNO())
                << std::endl;
    }
  }

  std::cerr << "[Debug] "s << conn_info.ToString() << " ("s << packet_length
            << " bytes): '"s << writable_buffer << "'\n"s;
  return recv_bytes;
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::cerr << "[Usage] server <address> <port>" << std::endl;
    return 1;
  }
#ifdef _WIN32
  WSADATA d;
  if (WSAStartup(MAKEWORD(2, 2), &d)) {
    std::cerr << "Failed to initialize WinSockAPI: "
              << std::system_category().message(GET_SOCKET_ERRNO())
              << std::endl;
    return 1;
  }
#endif

  Server server(argv[1], argv[2]);
  if (server.Start() == -1) {
    return 1;
  }
}
