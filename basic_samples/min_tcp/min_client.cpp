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
  int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (clientSocket == -1) {
    std::cerr << "Error creating socket\n";
    return -1;
  }

  // Connect to the server
  sockaddr_in serverAddr{};
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(PORT);
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(clientSocket, (struct sockaddr*)&serverAddr,
              sizeof(serverAddr)) == -1) {
    std::cerr << "Error connecting to server\n";
    close(clientSocket);
    return -1;
  }

  std::cout << "Connected to server\n";

  // Send messages to the server
  while (true) {
    // Example: Send a message of type 1
    char messageData[1024];
    std::cout << "Enter a message: ";
    std::cin.getline(messageData, sizeof(messageData));

    Message sendMessage;
    sendMessage.type = 1;
    strcpy(sendMessage.data, messageData);

    send(clientSocket, &sendMessage, sizeof(sendMessage), 0);

    // Receive and process the server's response
    Message receivedMessage;
    recv(clientSocket, &receivedMessage, sizeof(receivedMessage), 0);

    std::cout << "Server response of type " << receivedMessage.type << ": "
              << receivedMessage.data << std::endl;
  }

  // Close the client socket
  close(clientSocket);

  return 0;
}
