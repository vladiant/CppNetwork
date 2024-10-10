#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* port users are connection to - 0 for random unused port */
#define MYPORT 3334

int main() {
  char *a1, *a2;

  /* Socket addresses */
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(MYPORT);
  /* return -1 on failure otherwise in_addr_t*/
  /*
  server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  printf("inet_addr_result: %d\n",server_addr.sin_addr.s_addr);
  */

  /* returns non-zero on success, and zero on failure */
  /* non standard */
  int aton_result = inet_aton("192.168.4.1", &(server_addr.sin_addr));
  printf("server_addr aton result: %d\n", aton_result);
  /* zero the rest of the struct */
  memset(&(server_addr.sin_zero), 0, sizeof(server_addr.sin_zero));

  a1 = inet_ntoa(server_addr.sin_addr);
  printf("server_addr sin_addr: %s\n", a1);

  struct sockaddr_in my_addr;
  /*
  POSIX compilant
  returns non-zero on success, and zero on failure
  */
  int pton_result = inet_pton(AF_INET, "10.11.110.55", &(my_addr.sin_addr));
  printf("my_addr pton result: %d\n", pton_result);

  /* zero the rest of the struct */
  memset(&(my_addr.sin_zero), 0, sizeof(my_addr.sin_zero));

  a2 = inet_ntoa(my_addr.sin_addr);
  printf("my_addr sin_addr: %s\n", a2);

  /* a1 and a2 are the same - so data should be copied */
  printf("server_addr sin_addr revisited: %s\n", a1);

  return EXIT_SUCCESS;
}
