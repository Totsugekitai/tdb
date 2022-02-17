#include <stdio.h>

const char *str = "panda";

static int func1(int p1) {
  printf("hello world %x %s\n", p1, str);
  return 0;
}

static int func2(int p2) { return func1(p2 + 0xcafe); }

int main(void) {
  register int p = 0xbeef;
  return func2(p);
}
