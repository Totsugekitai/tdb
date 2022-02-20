#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

// static void handler(int sig, siginfo_t *si, void *unused) {
//   printf("SIGSEGV");
//   raise(SIGSEGV);
//   exit(0);
// }

int main(int argc, char *argv[]) {
  //   struct sigaction sa;

  //   sa.sa_flags = SA_SIGINFO;
  //   sigemptyset(&sa.sa_mask);
  //   sa.sa_sigaction = handler;
  //   if (sigaction(SIGSEGV, &sa, NULL) == -1) {
  //     fprintf(stderr, "sigaction");
  //     return 1;
  //   }

  volatile char *invalid = (volatile char *)0x0000555555556000;
  *invalid = 'c';
  printf("%c\n", *invalid);
  return 0;
}