#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Iterative Connection-Oriented Server*/

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

void TCPdaytimed(int fd) {
  char *pts;
  time_t now;
  char *ctime();

  time(&now);

  pts = ctime(&now);

  write(fd, pts, strlen(pts));
}

int main() {
  struct sockaddr_in fsin;
  char *service = "daytime";
  int msock, ssock;
  unsigned int alen;

  msock = passiveTCP(service, 5);

  while (1) {
    ssock = accept(msock, (struct sockaddr *)&fsin, &alen);

    if (ssock < 0) {
      printf("accept failed: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    TCPdaytimed(ssock);

    close(ssock);
  }

  return EXIT_SUCCESS;
}