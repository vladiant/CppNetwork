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
  /* listen on sock_fd, new connection on new_fd */
  int sock_fd, new_fd;

  /* my address information */
  struct sockaddr_in my_addr;

  /* remote address information */
  struct sockaddr their_addr;

  /* domain, type, protocol */
  /* for SOCK_STREAM protocol can be IPPROTO_TCP */
  sock_fd = socket(AF_INET, SOCK_STREAM, 0);

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

  if (listen(sock_fd, BACKLOG) == -1) {
    perror("Server listen error!\n");
  }

  printf("Server listen() is OK...\n");

  /* Accept connections and handle messages */
  /* while (1) */ {
    /* code to read the received data */
    socklen_t sin_size;
    sin_size = sizeof(struct sockaddr_in);
    new_fd = accept(sock_fd, &their_addr, &sin_size);

    if (new_fd == -1) {
      perror("Server accept error!\n");
    } else {
      printf("Server accept() is OK...\n");
    }

    /* Handle messages from the client */
    char msg[12];
    while (recv(new_fd, &msg, sizeof(msg), 0) > 0) {
      printf("Received message: %s\n", msg);
    }

    printf("Close read socket %d\n", close(new_fd));
  }

  printf("Close listen socket %d\n", close(sock_fd));

  return EXIT_SUCCESS;
}
