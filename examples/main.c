//go:build exclude

#include <stdio.h>
#include <unistd.h>

int main() {
  printf("pre-fork\n");
  printf("%d\n", getpid());
  sleep(1);
  fork();
  while (1) {
    sleep(1);
    printf(".\n");
    sleep(1);
    printf(" .\n");
    fflush(stdout);
  }
}
