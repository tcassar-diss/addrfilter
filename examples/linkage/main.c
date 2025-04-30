#include "printf.h"
#include "getpid.h"
#include <unistd.h>

int main() {
    // sleep for 0.375 of a second: addrfilter boot coverage limitation
    usleep(375000);

    // make a syscall from the getpid .so (getpid is syscall number 39)
    pid_t pid = wrap_getpid();
    
    // make a syscall from the printf .so (printf calls write: syscall number 1)
    wrap_printf("hello from process %d!\n", pid);
}
