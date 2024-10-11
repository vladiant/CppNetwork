#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int main() {
  const char* hostname = "google.com";

  struct hostent* host_info = gethostbyname(hostname);
  if (!host_info) {
    perror(hostname);
    return EXIT_FAILURE;
  }

  printf("h_name: %s\n", host_info->h_name);

  if (host_info->h_addr_list) {
    printf("h_addr_list size: %ld\n", sizeof(host_info->h_addr_list));
    for (unsigned long i = 0; i < sizeof(host_info->h_addr_list); i++) {
      if (!host_info->h_addr_list[i]) {
        break;
      }
      struct in_addr addr;
      memcpy((char*)&addr, host_info->h_addr_list[i], sizeof(addr));
      printf("h_address[%ld]: %s\n", i, inet_ntoa(addr));
    }
  }

  if (host_info->h_aliases) {
    printf("h_aliases size: %ld\n", sizeof(host_info->h_aliases));
    for (unsigned long i = 0; i < sizeof(host_info->h_aliases); i++) {
      if (!host_info->h_aliases[i]) {
        break;
      }
      printf("h_aliases[%ld]: %s\n", i, host_info->h_aliases[i]);
    }
  }

  /* http://www.iana.org/assignments/port-numbers */
  const char* servname = "domain";

  /* name, proto */
  /* when proto is NULL any protocol is matched */
  /* struct servent* server_info = getservent(); */
  struct servent* server_info = getservbyname("domain", "tcp");
  if (!server_info) {
    perror(servname);
    return EXIT_FAILURE;
  }

  printf("s_name: %s\n", server_info->s_name);
  printf("s_port: %d\n", server_info->s_port);
  printf("s_proto: %s\n", server_info->s_proto);

  if (server_info->s_aliases) {
    printf("s_aliases size: %ld\n", sizeof(server_info->s_aliases));
    for (unsigned long i = 0; i < sizeof(server_info->s_aliases); i++) {
      if (!server_info->s_aliases[i]) {
        break;
      }
      printf("s_aliases[%ld]: %s\n", i, server_info->s_aliases[i]);
    }
  }

  /* http://www.iana.org/assignments/port-numbers */
  const char* protoname = "tcp";

  struct protoent* proto_info = getprotobyname(protoname);
  if (!proto_info) {
    perror(protoname);
    return EXIT_FAILURE;
  }

  printf("p_name: %s\n", proto_info->p_name);
  printf("p_proto: %d\n", proto_info->p_proto);

  if (proto_info->p_aliases) {
    printf("p_aliases size: %ld\n", sizeof(proto_info->p_aliases));
    for (unsigned long i = 0; i < sizeof(proto_info->p_aliases); i++) {
      if (!proto_info->p_aliases[i]) {
        break;
      }
      printf("p_aliases[%ld]: %s\n", i, proto_info->p_aliases[i]);
    }
  }

  return EXIT_SUCCESS;
}
