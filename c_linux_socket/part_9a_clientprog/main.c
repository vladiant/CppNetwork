/*** a stream socket client demo ***/
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* the port client will be connecting to */
#define PORT 3490

/* max number of bytes we can get at once */
#define MAXDATASIZE 300

int main(int argc, char *argv[]) {
  int sockfd, numbytes;
  char buf[MAXDATASIZE];

  struct hostent *he;

  /* connector’s address information */
  struct sockaddr_in their_addr;

  /* if no command line argument supplied */
  if (argc != 2) {
    fprintf(stderr, "Client-Usage: %s the_client_hostname\n", argv[0]);
    /* just exit */
    exit(EXIT_FAILURE);
  }

  /* get the host info */
  if ((he = gethostbyname(argv[1])) == NULL) {
    perror("gethostbyname()");
    exit(EXIT_FAILURE);
  }

  printf("Client-The remote host is: %s\n", argv[1]);

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  printf("Client-The socket() sockfd is OK...\n");

  /* host byte order */
  their_addr.sin_family = AF_INET;

  /* short, network byte order */
  printf("Server-Using %s and port %d...\n", argv[1], PORT);
  their_addr.sin_port = htons(PORT);

  their_addr.sin_addr = *((struct in_addr *)he->h_addr_list[0]);

  /* zero the rest of the struct */
  memset(&(their_addr.sin_zero), '\0', 8);

  if (connect(sockfd, (struct sockaddr *)&their_addr,
              sizeof(struct sockaddr)) == -1) {
    perror("connect()");
    exit(EXIT_FAILURE);
  }

  printf("Client-The connect() is OK...\n");

  if ((numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0)) == -1) {
    perror("recv()");
    exit(EXIT_FAILURE);
  }

  printf("Client-The recv() is OK...\n");

  buf[numbytes] = '\0';

  printf("Client-Received: %s", buf);

  printf("Client-Closing sockfd\n");
  close(sockfd);

  return EXIT_SUCCESS;
}