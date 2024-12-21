#include "utils.h"

#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include <string.h>
#include <stdlib.h>

char *xstrndup(const char *s, size_t n) {
    char *d = malloc(n + 1);
    if(d == NULL) {
        return NULL;
    }
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

int xfullread(int fd, int eof, void *buffer, size_t bufsize) {
    ssize_t       ssz;
    size_t        sz;
    struct pollfd pfd;
    int           rc;

    pfd.fd = fd;
    pfd.events = POLLIN;

    for(sz = 0; sz < bufsize; sz += ssz) {
        if((rc = poll(&pfd, 1, -1)) < 0) {
            if(errno == EINTR) {
                continue;
            }
            return -1;
        } else if(rc == 0) {
            ssz = 0;
            continue;
        }

        if(!(pfd.revents & POLLIN)) {
            if(eof && sz == 0) {
                return 0;
            }
            return -1;
        }

        if((ssz = read(fd, buffer + sz, bufsize - sz)) < 0) {
            if(errno == EINTR) {
                ssz = 0;
                continue;
            }
            return -1;
        } else if(ssz == 0 && sz > 0) {
            return -1;
        } else if(ssz == 0 && sz == 0 && !eof) {
            return -1;
        } else if(ssz == 0 && sz == 0 && eof) {
            return 0;
        } else if(sz > SIZE_MAX - ssz) {
            return -1;
        }
    }
    return 1;
}

int xfullwrite(int fd, const void *s, size_t n) {
    ssize_t       ssz;
    size_t        sz;
    struct pollfd pfd;
    int           rc;

    pfd.fd = fd;
    pfd.events = POLLOUT;

    for(sz = 0; sz < n; sz += ssz) {
        if((rc = poll(&pfd, 1, -1)) < 0) {
            if(errno == EINTR) {
                continue;
            }
            return -1;
        } else if(rc == 0) {
            ssz = 0;
            continue;
        }

        if(!(pfd.revents & POLLOUT)) {
            return -1;
        }

        if((ssz = write(fd, s + sz, n - sz)) < 0) {
            if(errno == EINTR) {
                ssz = 0;
                continue;
            }
            return -1;
        } else if(ssz == 0 && sz > 0) {
            return -1;
        } else if(ssz == 0 && sz == 0) {
            return -1;
        } else if(sz > SIZE_MAX - ssz) {
            return -1;
        }
    }
}

int xreaddiscard(int fd, size_t buf) {
    if(buf > 255) {
        return -1;
    }

    char buffer[256];
    return xfullread(fd, 0, buffer, buf);
}