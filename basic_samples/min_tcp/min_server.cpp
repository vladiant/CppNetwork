#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

const int PORT = 8080;

// Define your messaging protocol
struct Message {
  int type;         // You can define different message types
  char data[1024];  // Actual message data
};

int main() {
  // Create socket
  int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket == -1) {
    std::cerr << "Error creating socket\n";
    return -1;
  }

  // Bind the socket to a specific address and port
  sockaddr_in serverAddr{};
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(PORT);
  serverAddr.sin_addr.s_addr = INADDR_ANY;

  if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) ==
      -1) {
    std::cerr << "Error binding socket\n";
    close(serverSocket);
    return -1;
  }

  // Listen for incoming connections
  if (listen(serverSocket, 10) == -1) {
    std::cerr << "Error listening for connections\n";
    close(serverSocket);
    return -1;
  }

  std::cout << "Server listening on port " << PORT << std::endl;

  // Accept connections and handle messages
  while (true) {
    sockaddr_in clientAddr{};
    socklen_t clientLen = sizeof(clientAddr);
    int clientSocket =
        accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);

    if (clientSocket == -1) {
      std::cerr << "Error accepting connection\n";
      continue;
    }

    std::cout << "Connection accepted from " << inet_ntoa(clientAddr.sin_addr)
              << std::endl;

    // Handle messages from the client
    Message receivedMessage;
    while (recv(clientSocket, &receivedMessage, sizeof(receivedMessage), 0) >
           0) {
      // Process the received message
      std::cout << "Received message of type " << receivedMessage.type << ": "
                << receivedMessage.data << std::endl;

      // Example: Respond to the client
      Message responseMessage;
      responseMessage.type = 1;
      strcpy(responseMessage.data, "Hello, client!");
      send(clientSocket, &responseMessage, sizeof(responseMessage), 0);
    }

    close(clientSocket);
    std::cout << "Connection closed with " << inet_ntoa(clientAddr.sin_addr)
              << std::endl;
  }

  // Close the server socket
  close(serverSocket);

  return 0;
}
