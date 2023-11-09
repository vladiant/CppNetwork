#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* 0 for random unused port*/
#define MYPORT 3334

int main() {
  /* socket file descriptor */
  int sockfd;
  struct sockaddr_in my_addr;

  /* domain, type, protocol*/
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("Server socket error!\n");
    exit(EXIT_FAILURE);
  }

  printf("Server socket() sockfd is OK...\n");

  /* host byte order */
  my_addr.sin_family = AF_INET;
  /* short network byte order */
  my_addr.sin_port = htons(MYPORT);
  /* use my IP address */
  my_addr.sin_addr.s_addr = INADDR_ANY;
  /* zero the rest of the struct */
  memset(&(my_addr.sin_zero), 0, sizeof(my_addr.sin_zero));

  if (bind(sockfd, (struct sockaddr*)&my_addr, sizeof(struct sockaddr)) == -1) {
    perror("Server bind error!\n");
    exit(EXIT_FAILURE);
  }

  printf("Server bind() is OK...\n");

  printf("Close socket %d\n", close(sockfd));

  return EXIT_SUCCESS;
}
