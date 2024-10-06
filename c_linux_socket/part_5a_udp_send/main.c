#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* port users are connection to - 0 for random unused port */
#define MYPORT 3334

/* how many connections queue will hold */
#define BACKLOG 10

int main() {
  /* send on sock_fd */
  int sock_fd;

  /* domain, type, protocol */
  /* for SOCK_DGRAM protocol can be IPPROTO_UDP */
  sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sock_fd == -1) {
    perror("Server socket error!\n");
    exit(EXIT_FAILURE);
  }

  printf("Server socket() sock_fd is OK...\n");

  /* Connect to the server */
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(MYPORT);
  server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) ==
      -1) {
    perror("Error connecting to server\n");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  /* while (1) */ {
    char *msg = "I was here!";

    int len, bytes_sent;
    len = strlen(msg);
    /* flag set to 0 */
    bytes_sent = send(sock_fd, msg, len, 0);
    printf("bytes_sent %d\n", bytes_sent);
  }

  printf("Close send socket %d\n", close(sock_fd));

  return EXIT_SUCCESS;
}
