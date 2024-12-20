#include "util.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

char *xaprintf(const char *fmt, ...) {
    char *ret;
    va_list va;
    va_start(va, fmt);
    ret = xvaprintf(fmt, va);
    va_end(va);
    return ret;
}

char *xvaprintf(const char *fmt, va_list va) {
    va_list ap;
    va_copy(ap, va);
    size_t buf = snprintf(NULL, 0, fmt, ap);
    va_end(ap);
    char *buffer = malloc(sizeof(char) * (buf + 1));
    if(!buffer) {
        return NULL;
    }
    snprintf(buffer, buf, fmt, va);
    buffer[buf] = '\0';
    return buffer;
}