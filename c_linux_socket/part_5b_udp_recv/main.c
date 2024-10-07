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
  /* listen on sock_fd */
  int sock_fd;

  /* my address information */
  struct sockaddr_in my_addr;

  /* domain, type, protocol */
  /* for SOCK_DGRAM protocol can be IPPROTO_UDP */
  sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sock_fd == -1) {
    perror("Server socket error!\n");
    exit(EXIT_FAILURE);
  }

  printf("Server socket() sock_fd is OK...\n");

  /* host byte order */
  my_addr.sin_family = AF_INET;
  /* short network byte order */
  my_addr.sin_port = htons(MYPORT);
  /* use my IP address */
  my_addr.sin_addr.s_addr = INADDR_ANY;
  /* zero the rest of the struct */
  memset(&(my_addr.sin_zero), 0, sizeof(my_addr.sin_zero));

  if (bind(sock_fd, (struct sockaddr*)&my_addr, sizeof(struct sockaddr)) ==
      -1) {
    perror("Server bind error!\n");
    exit(EXIT_FAILURE);
  }

  printf("Server bind() is OK...\n");

  /* Handle messages from the client */
  char msg[12];
  /* blocking call */
  while (recv(sock_fd, &msg, sizeof(msg), 0) > 0) {
    printf("Received message: %s\n", msg);
  }

  printf("Close listen socket %d\n", close(sock_fd));

  return EXIT_SUCCESS;
}
