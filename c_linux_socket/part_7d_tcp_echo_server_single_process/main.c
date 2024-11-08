#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Single-Process Concurrent Server */

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

int echo(int fd) {
  char buf[BUFSIZ];
  int cc;

  cc = read(fd, buf, sizeof buf);
  if (cc < 0) {
    printf("echo read: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (cc && write(fd, buf, cc) < 0) {
    printf("echo write: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return cc;
}

#define QLEN 10

int main() {
  char *service = "echo";
  struct sockaddr_in fsin;
  int msock;
  fd_set rfds;
  fd_set afds;
  unsigned int alen;
  int fd, nfds;

  msock = passiveTCP(service, QLEN);

  nfds = getdtablesize();

  FD_ZERO(&afds);

  FD_SET(msock, &afds);

  while (1) {
    memcpy(&rfds, &afds, sizeof(rfds));

    if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0, (struct timeval *)0) <
        0) {
      printf("select: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (FD_ISSET(msock, &rfds)) {
      int ssock;
      alen = sizeof(fsin);
      ssock = accept(msock, (struct sockaddr *)&fsin, &alen);

      if (ssock < 0) {
        printf("accept: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
      }

      FD_SET(ssock, &afds);
    }

    for (fd = 0; fd < nfds; ++fd) {
      if (fd != msock && FD_ISSET(fd, &rfds)) {
        if (echo(fd) == 0) {
          (void)close(fd);
          FD_CLR(fd, &afds);
        }
      }
    }
  }

  return EXIT_SUCCESS;
}