/* Receiver/client multicast Datagram example. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct sockaddr_in localSock;
struct ip_mreq group;
int sd;
int datalen;

char databuf[1024];

int main() {
  /* Create a datagram socket on which to receive. */

  sd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sd < 0) {
    perror("Opening datagram socket error");
    exit(EXIT_FAILURE);
  }

  printf("Opening datagram socket....OK.\n");

  /* Enable SO_REUSEADDR to allow multiple instances of this */
  /* application to receive copies of the multicast datagrams. */

  {
    int reuse = 1;

    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
                   sizeof(reuse)) < 0) {
      perror("Setting SO_REUSEADDR error");
      close(sd);
      exit(EXIT_FAILURE);
    }

    printf("Setting SO_REUSEADDR...OK.\n");
  }

  /* Bind to the proper port number with the IP address */
  /* specified as INADDR_ANY. */
  memset((char *)&localSock, 0, sizeof(localSock));
  localSock.sin_family = AF_INET;
  localSock.sin_port = htons(4321);
  localSock.sin_addr.s_addr = INADDR_ANY;

  if (bind(sd, (struct sockaddr *)&localSock, sizeof(localSock))) {
    perror("Binding datagram socket error");
    close(sd);
    exit(EXIT_FAILURE);
  }

  printf("Binding datagram socket...OK.\n");

  /* Join the multicast group 226.1.1.1 on the local 203.106.93.94 */
  /* interface. Note that this IP_ADD_MEMBERSHIP option must be */
  /* called for each local interface over which the multicast */
  /* datagrams are to be received. */
  group.imr_multiaddr.s_addr = inet_addr("226.1.1.1");
  group.imr_interface.s_addr = inet_addr("203.106.93.94");

  if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group,
                 sizeof(group)) < 0) {
    perror("Adding multicast group error");
    close(sd);
    exit(EXIT_FAILURE);
  }

  printf("Adding multicast group...OK.\n");

  /* Read from the socket. */
  datalen = sizeof(databuf);
  if (read(sd, databuf, datalen) < 0) {
    perror("Reading datagram message error");
    close(sd);
    exit(EXIT_FAILURE);
  }

  printf("Reading datagram message...OK.\n");
  printf("The message from multicast server is: \"%s\"\n", databuf);

  return EXIT_FAILURE;
}