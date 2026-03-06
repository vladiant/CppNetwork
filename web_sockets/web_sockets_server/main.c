/* https://kevwe.com/blog/websockets-in-c-with-wsserver */

#include <stdio.h>
#include <stdlib.h>
#include <ws.h>

void onopen(ws_cli_conn_t *fd) {
  char *cli;
  cli = ws_getaddress(fd);
  printf("Connection opened, client: %p | addr: %s\n", (void *)fd, cli);
}

void onmessage(ws_cli_conn_t *fd, const unsigned char *msg, size_t size,
               int type) {
  char *cli;
  cli = ws_getaddress(fd);
  printf("Received message: [%s] (size: %zu, type: %d), from: %s/%p\n", msg,
         size, type, cli, (void *)fd);

  ws_sendframe(fd, (char *)msg, size, type);
}

void onclose(ws_cli_conn_t *fd) {
  char *cli;
  cli = ws_getaddress(fd);
  printf("Connection closed, client: %p | addr: %s\n", (void *)fd, cli);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  struct ws_events evs;
  evs.onopen = &onopen;
  evs.onclose = &onclose;
  evs.onmessage = &onmessage;
  ws_socket(&evs, 8080, 0, 1000);

  return (0);
}