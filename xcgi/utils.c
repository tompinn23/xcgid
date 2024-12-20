#include "utils.h"

char *xstrndup(const char *s, size_t n) {
    char *d = malloc(n + 1);
    if(d == NULL) {
        return NULL;
    }
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}