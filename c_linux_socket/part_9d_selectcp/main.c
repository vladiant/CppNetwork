/* a select() demo */
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* file descriptor for standard input */
#define STDIN 0

int main() {
  struct timeval tval;
  fd_set readfds;
  tval.tv_sec = 5;
  tval.tv_usec = 800000;

  FD_ZERO(&readfds);
  FD_SET(STDIN, &readfds);

  /* don’t care about writefds and exceptfds: */
  select(STDIN + 1, &readfds, NULL, NULL, &tval);

  if (FD_ISSET(STDIN, &readfds)) {
    printf("A key was pressed lor!\n");
  } else {
    printf("Timed out lor!...\n");
  }

  return 0;
}