#include "printf.h"
#include "getpid.h"
#include <stdio.h>
#include <unistd.h>

int main() {

    sleep(1);
    fprintf(stderr, "address of wrap_getpid = %p\n", wrap_getpid);
    fprintf(stderr, "address of wrap_printf = %p\n", wrap_printf);


    pid_t pid = wrap_getpid();
    wrap_printf("hello from process %d!\n", pid);
}
