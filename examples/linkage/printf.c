#include "printf.h"
#include <stdarg.h>
#include <stdio.h>

int wrap_printf(const char *__restrict__ format, ...) {
    va_list ap;
    va_start(ap, format);
    int n = vprintf(format, ap);
    va_end(ap);
    return n;
}
