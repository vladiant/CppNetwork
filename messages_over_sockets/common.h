#pragma once

#ifdef _WIN32                // If host's OS is Windows
#ifndef _WIN32_WINNT         // Necessary for properly initializing WindowsAPI
#define _WIN32_WINNT 0x0600  // minimum - Windows Vista (0x0600)
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")  // For VS compiler
#else                               // Other UNIX-like OSes
#include <arpa/inet.h>
#include <errno.h>  // For getting error codes
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <cstring>
#include <ctime>
#include <iostream>
#include <string>

// Cross-Platform macros
#ifdef _WIN32
#define CLOSE_SOCKET(s) closesocket(s)
#define GET_SOCKET_ERRNO() (WSAGetLastError())
#define IS_VALID_SOCKET(s) ((s) != INVALID_SOCKET)
#else
#define SOCKET int
#define CLOSE_SOCKET(s) close(s)
#define GET_SOCKET_ERRNO() (errno)
#define IS_VALID_SOCKET(s) ((s) >= 0)
#endif

#define MAX_DATA_BUFFER_SIZE 2048

// Adds 4-digit length to the beginning of the message string: message.size() ==
// 4 -> "0004<message_string>"; message.size() == 1002 -> "1002<message_string>"
void PrependMessageLength(std::string& message) {
  std::string message_size_str = std::to_string(message.size());
  while (message_size_str.size() < 4) {
    message_size_str = "0" + message_size_str;
  }
  message = message_size_str + message;
}