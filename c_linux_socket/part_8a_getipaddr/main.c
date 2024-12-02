/****a hostname lookup program example******/
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
  struct hostent *h;

  /* error check the command line */
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <domain_name>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  /* get the host info */
  if ((h = gethostbyname(argv[1])) == NULL) {
    perror("gethostbyname(): ");
    exit(EXIT_FAILURE);
  }

  printf("gethostbyname() is OK.\n");

  printf("The host name is: %s\n", h->h_name);
  struct in_addr addr;
  memcpy((char *)&addr, h->h_addr_list[0], sizeof(addr));
  printf("The IP Address is: %s\n", inet_ntoa(addr));
  printf("The address length is: %d\n", h->h_length);

  printf("Sniffing other names...sniff...sniff...sniff...\n");

  int j = 0;
  do {
    printf("An alias #%d is: %s\n", j, h->h_aliases[j]);
    if (h->h_aliases[j] == NULL) {
      break;
    }
    j++;
  } while (h->h_aliases[j] != NULL);

  printf("Sniffing other IPs...sniff....sniff...sniff...\n");

  int i = 0;
  do {
    printf("Address #%i is: %s\n", i,
           inet_ntoa(*((struct in_addr *)(h->h_addr_list[i]))));
    i++;
  } while (h->h_addr_list[i] != NULL);

  return EXIT_SUCCESS;
}