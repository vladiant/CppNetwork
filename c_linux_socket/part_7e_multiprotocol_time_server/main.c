#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Multiprotocol Server*/

unsigned short portbase = 0;

int passivesock(const char *service, const char *transport, int qlen) {
  struct servent *pse;
  struct protoent *ppe;
  struct sockaddr_in sin;
  int s, type;

  memset(&sin, 0, sizeof(sin));

  sin.sin_family = AF_INET;

  sin.sin_addr.s_addr = INADDR_ANY;

  /* Map service name to port number */
  pse = getservbyname(service, transport);
  if (pse) {
    sin.sin_port = htons(ntohs((unsigned short)pse->s_port) + portbase);
  } else if ((sin.sin_port = htons((unsigned short)atoi(service))) == 0) {
    printf("can't get \"%s\" service entry\n", service);
    exit(EXIT_FAILURE);
  }

  /* Map protocol name to protocol number */
  if ((ppe = getprotobyname(transport)) == 0) {
    printf("can't get \"%s\" protocol entry\n", transport);
    exit(EXIT_FAILURE);
  }

  /* Use protocol to choose a socket type */
  if (strcmp(transport, "udp") == 0) {
    type = SOCK_DGRAM;
  } else {
    type = SOCK_STREAM;
  }

  /* Allocate a socket */
  s = socket(PF_INET, type, ppe->p_proto);
  if (s < 0) {
    printf("can't create socket: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Bind the socket */
  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    printf("can't bind to %s port: %s\n", service, strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (type == SOCK_STREAM && listen(s, qlen) < 0) {
    printf("can't listen on %s port: %s\n", service, strerror(errno));
    exit(EXIT_FAILURE);
  }

  return s;
}

int passiveUDP(const char *service) { return passivesock(service, "udp", 0); }

int passiveTCP(const char *service, int qlen) {
  return passivesock(service, "tcp", qlen);
}

void daytime(char buf[]) {
  time_t now;

  (void)time(&now);

  sprintf(buf, "%s", ctime(&now));
}

#define QLEN 10
#define LINELEN 80

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

int main() {
  char *service = "daytime"; /* service name or port number */
  char buf[LINELEN + 1];     /* buffer for one line of text */
  struct sockaddr_in fsin;   /* the request from address */
  unsigned int alen;         /* from-address length  */
  int tsock;                 /* TCP master socket  */
  int usock;                 /* UDP socket  */
  int nfds;
  fd_set rfds; /* readable file descriptors */

  tsock = passiveTCP(service, QLEN);

  usock = passiveUDP(service);

  /* bit number of max fd */
  nfds = MAX(tsock, usock) + 1;

  FD_ZERO(&rfds);

  while (1) {
    FD_SET(tsock, &rfds);
    FD_SET(usock, &rfds);

    if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0, (struct timeval *)0) <
        0) {
      printf("select error: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (FD_ISSET(tsock, &rfds)) {
      /* TCP slave socket */
      int ssock;

      alen = sizeof(fsin);

      ssock = accept(tsock, (struct sockaddr *)&fsin, &alen);

      if (ssock < 0) {
        printf("accept failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
      }

      daytime(buf);

      (void)write(ssock, buf, strlen(buf));

      (void)close(ssock);
    }

    if (FD_ISSET(usock, &rfds)) {
      alen = sizeof(fsin);

      if (recvfrom(usock, buf, sizeof(buf), 0, (struct sockaddr *)&fsin,
                   &alen) < 0) {
        printf("recvfrom: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
      }

      daytime(buf);

      (void)sendto(usock, buf, strlen(buf), 0, (struct sockaddr *)&fsin,
                   sizeof(fsin));
    }
  }

  return EXIT_SUCCESS;
}
