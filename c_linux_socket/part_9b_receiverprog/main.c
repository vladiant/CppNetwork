/* a server, datagram sockets */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* the port users will be connecting to */
#define MYPORT 4950
#define MAXBUFLEN 500

int main() {
  int sockfd;

  /* my address information */
  struct sockaddr_in my_addr;

  /* connector’s address information */
  struct sockaddr_in their_addr;

  unsigned int addr_len;
  int numbytes;

  char buf[MAXBUFLEN];

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("Server-socket() sockfd error lol!");
    exit(EXIT_FAILURE);
  }

  printf("Server-socket() sockfd is OK...\n");

  /* host byte order */
  my_addr.sin_family = AF_INET;

  /* short, network byte order */
  my_addr.sin_port = htons(MYPORT);

  /* automatically fill with my IP */
  my_addr.sin_addr.s_addr = INADDR_ANY;

  /* zero the rest of the struct */
  memset(&(my_addr.sin_zero), '\0', 8);

  if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) ==
      -1) {
    perror("Server-bind() error lol!");
    exit(EXIT_FAILURE);
  }

  printf("Server-bind() is OK...\n");

  addr_len = sizeof(struct sockaddr);

  if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN - 1, 0,
                           (struct sockaddr *)&their_addr, &addr_len)) == -1) {
    perror("Server-recvfrom() error lol!");
    /* If something wrong, just exit lol... */
    exit(EXIT_FAILURE);
  }

  printf("Server-Waiting and listening...\n");

  printf("Server-recvfrom() is OK...\n");

  printf("Server-Got packet from %s\n", inet_ntoa(their_addr.sin_addr));

  printf("Server-Packet is %d bytes long\n", numbytes);

  buf[numbytes] = '\0';

  printf("Server-Packet contains \"%s\"\n", buf);

  if (close(sockfd) != 0) {
    printf("Server-sockfd closing failed!\n");
  } else {
    printf("Server-sockfd successfully closed!\n");
  }

  return EXIT_SUCCESS;
}