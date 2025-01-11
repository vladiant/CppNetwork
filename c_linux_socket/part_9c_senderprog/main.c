/* a client, datagram */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* the port users will be connecting to */
#define MYPORT 4950

int main(int argc, char *argv[]) {
  int sockfd;

  /* connector’s address information */
  struct sockaddr_in their_addr;

  struct hostent *he;
  int numbytes;

  if (argc != 3) {
    fprintf(stderr, "Client-Usage: %s <hostname> <message>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  /* get the host info */
  if ((he = gethostbyname(argv[1])) == NULL) {
    perror("Client-gethostbyname() error lol!");
    exit(EXIT_FAILURE);
  }

  printf("Client-gethostname() is OK...\n");

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("Client-socket() error lol!");
    exit(EXIT_FAILURE);
  }

  printf("Client-socket() sockfd is OK...\n");

  /* host byte order */
  their_addr.sin_family = AF_INET;

  /* short, network byte order */
  printf("Using port: 4950\n");

  their_addr.sin_port = htons(MYPORT);
  their_addr.sin_addr = *((struct in_addr *)he->h_addr_list[0]);

  /* zero the rest of the struct */
  memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));

  if ((numbytes = sendto(sockfd, argv[2], strlen(argv[2]), 0,
                         (struct sockaddr *)&their_addr,
                         sizeof(struct sockaddr))) == -1) {
    perror("Client-sendto() error lol!");
    exit(EXIT_FAILURE);
  }

  printf("Client-sendto() is OK...\n");

  printf("sent %d bytes to %s\n", numbytes, inet_ntoa(their_addr.sin_addr));

  if (close(sockfd) != 0) {
    printf("Client-sockfd closing is failed!\n");
  } else {
    printf("Client-sockfd successfully closed!\n");
  }

  return EXIT_SUCCESS;
}