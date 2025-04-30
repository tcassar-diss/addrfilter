#include "getpid.h"

#include <unistd.h>


pid_t internal() {
    return getpid();
}

pid_t wrap_getpid() {
    return internal();
}
