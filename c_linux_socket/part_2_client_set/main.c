#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DEST_IP "127.0.0.1"
#define DEST_PORT 80

int main() {
  /* socket file descriptor */
  int sockfd;

  /* will hold the destination addr */
  struct sockaddr_in dest_addr;

  /* domain, type, protocol*/
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd == -1) {
    perror("Client socket error!\n");
    exit(EXIT_FAILURE);
  }

  printf("Client socket() sockfd is OK...\n");

  /* host byte order */
  dest_addr.sin_family = AF_INET;
  /* short network byte order */
  dest_addr.sin_port = htons(DEST_PORT);
  dest_addr.sin_addr.s_addr = inet_addr(DEST_IP);
  /* zero the rest of the struct */
  memset(&(dest_addr.sin_zero), 0, sizeof(dest_addr.sin_zero));

  if (connect(sockfd, (struct sockaddr*)&dest_addr, sizeof(struct sockaddr)) ==
      -1) {
    int errcl = errno;
    printf("Client connect error %d : %s !\n", errcl, strerror(errcl));

    exit(EXIT_FAILURE);
  }

  printf("Client connect() is OK...\n");

  printf("Close socket %d\n", close(sockfd));

  return EXIT_SUCCESS;
}
