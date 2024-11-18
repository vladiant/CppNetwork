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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Multiservice Server*/

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

int TCPechod(int fd) {
  char buf[BUFSIZ];
  int cc;

  while ((cc = read(fd, buf, sizeof buf))) {
    if (cc < 0) {
      printf("echo read: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (write(fd, buf, cc) < 0) {
      printf("echo write: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  return 0;
}

int TCPdaytimed(int fd) {
  char *pts;
  time_t now;
  char *ctime();

  time(&now);

  pts = ctime(&now);

  write(fd, pts, strlen(pts));

  return 0;
}

/* https://www.routeviews.org/stevens/v3.dist/examples/sv_funcs.c */

#define UNIXEPOCH 2208988800 /* UNIX epoch, in UCT secs	*/

/* do TCP TIME protocol */
int TCPtimed(int fd) {
  time_t now;

  (void)time(&now);
  now = htonl((unsigned long)(now + UNIXEPOCH));
  (void)write(fd, (char *)&now, sizeof(now));
  return 0;
}

int TCPchargend(int fd) {
  char c, buf[LINELEN + 2]; /* print LINELEN chars + \r\n */

  c = ' ';
  buf[LINELEN] = '\r';
  buf[LINELEN + 1] = '\n';
  while (1) {
    int i;

    for (i = 0; i < LINELEN; ++i) {
      buf[i] = c++;
      if (c > '~') c = ' ';
    }
    if (write(fd, buf, LINELEN + 2) < 0) break;
  }
  return 0;
}

struct service {
  char *sv_name;
  char sv_useTCP;
  int sv_sock;
  int (*sv_func)(int);
};

#define NOFILE 10
#define TCP_SERV 1
#define NOSOCK -1

struct service svent[] = {
    {"echo", TCP_SERV, NOSOCK, TCPechod},
    {"chargen", TCP_SERV, NOSOCK, TCPchargend},
    {"daytime", TCP_SERV, NOSOCK, TCPdaytimed},
    {"time", TCP_SERV, NOSOCK, TCPtimed},
    {0, 0, 0, 0},

};

/* doTCP() - handle a TCP service connection request */
void doTCP(struct service *psv) {
  /* the request from address */
  struct sockaddr_in fsin;

  /* from-address length */
  unsigned int alen;

  int fd, ssock;

  alen = sizeof(fsin);

  ssock = accept(psv->sv_sock, (struct sockaddr *)&fsin, &alen);

  if (ssock < 0) {
    printf("accept: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  switch (fork()) {
    case 0:
      break;
    case -1:
      printf("fork: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    default:
      (void)close(ssock);
      /* parent */
      return;
  }

  /* child */
  for (fd = NOFILE; fd >= 0; --fd) {
    if (fd != ssock) {
      (void)close(fd);
    }
  }

  exit(psv->sv_func(ssock));
}

/* reaper() - clean up zombie children */
void reaper(int sig) {
  int status;
  printf("signal: %d\n", sig);
  while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0) {
    /* empty */;
  }
}

int main() {
  struct service *psv, /* service table pointer */
      *fd2sv[NOFILE];  /* map fd to service pointer */

  int fd, nfds;
  fd_set afds, rfds; /* readable file descriptors */
  nfds = 0;

  FD_ZERO(&afds);

  for (psv = &svent[0]; psv->sv_name; ++psv) {
    if (psv->sv_useTCP) {
      psv->sv_sock = passiveTCP(psv->sv_name, QLEN);
    } else {
      psv->sv_sock = passiveUDP(psv->sv_name);
    }

    fd2sv[psv->sv_sock] = psv;
    nfds = MAX(psv->sv_sock + 1, nfds);
    FD_SET(psv->sv_sock, &afds);
  }

  (void)signal(SIGCHLD, reaper);

  while (1) {
    memcpy(&rfds, &afds, sizeof(rfds));
    if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0, (struct timeval *)0) <
        0) {
      if (errno == EINTR) {
        continue;
      }

      printf("select error: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    for (fd = 0; fd < nfds; ++fd) {
      if (FD_ISSET(fd, &rfds)) {
        psv = fd2sv[fd];
        if (psv->sv_useTCP) {
          doTCP(psv);
        } else {
          psv->sv_func(psv->sv_sock);
        }
      }
    }
  }

  return EXIT_SUCCESS;
}