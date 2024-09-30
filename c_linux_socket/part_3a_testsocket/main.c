#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MYPORT 3334

int main()

{
  int sockfd; /* socket file descriptor */

  struct sockaddr_in my_addr;

  /* 0 - socket chooses best protocol */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd == -1) {
    /*check errno */
    perror("Server-socket() error lol!");
    exit(EXIT_FAILURE);
  }

  printf("Server-socket() sockfd is OK...\n");

  /* host byte order */
  my_addr.sin_family = AF_INET;

  /* short, network byte order */
  /* choose an unused port at random my_addr.sin_port = 0; */
  my_addr.sin_port = htons(MYPORT);

  /* use my IP address */
  my_addr.sin_addr.s_addr = INADDR_ANY;

  /* zero the rest of the struct */
  memset(&(my_addr.sin_zero), 0, 8);

  /* go below 1024 for your port numbers - reserved!
  any port number above that, right up to 65535 */
  if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) ==
      -1) {
    /*check errno */
    perror("Server-bind() error lol!");
    exit(EXIT_FAILURE);
  }

  printf("Server-bind() is OK...\n");

  /*....other codes....*/
  int yes = 1;

  /* "Address already in use" error message */
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    /*check errno */
    perror("setsockopt() error");
    exit(EXIT_FAILURE);
  }

  printf("setsockopt() is OK.\n");

  return EXIT_SUCCESS;
}
