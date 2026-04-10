#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#define PORT 9034
#define MAX_EVENTS 10
#define BUFFER_SIZE 1024

int main() {
  int listen_fd, epoll_fd;
  struct sockaddr_in addr;
  struct epoll_event ev, events[MAX_EVENTS];

  // 1. Creating a listening socket
  listen_fd = socket(AF_INET, SOCK_STREAM, 0);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(PORT);

  bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
  listen(listen_fd, 10);

  // 2. Creating an epoll instance
  epoll_fd = epoll_create1(0);

  // Adding the listening socket to epoll
  ev.events = EPOLLIN;  // We are monitoring new connections.
  ev.data.fd = listen_fd;
  epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);

  printf("The Epoll server listens on port %d...\n", PORT);

  while (1) {
    // 3. Waiting for events
    int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

    for (int n = 0; n < nfds; n++) {
      if (events[n].data.fd == listen_fd) {
        // 4. Accepting a new connection
        int conn_fd = accept(listen_fd, NULL, NULL);
        ev.events = EPOLLIN;
        ev.data.fd = conn_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev);
        printf("New client added to epoll.\n");
      } else {
        // 5. Customer data processing
        char buffer[BUFFER_SIZE];
        int bytes = recv(events[n].data.fd, buffer, sizeof(buffer), 0);

        if (bytes <= 0) {
          // Remove on close or error
          epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[n].data.fd, NULL);
          close(events[n].data.fd);
          printf("The client has shut down.\n");
        } else {
          send(events[n].data.fd, buffer, bytes, 0);
        }
      }
    }
  }

  close(listen_fd);
  return 0;
}
