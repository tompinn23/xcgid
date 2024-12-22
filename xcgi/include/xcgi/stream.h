#pragma once

#include "xcgi/pool.h"

#include <stddef.h>

#include <stdint.h>

typedef struct xcgi_strm xcgi_strm;

typedef int64_t (*xcgi_reader)(struct xcgi_strm *s, const void **buffer);
/** when called with -1 for size we expect to be told what chunks we should be writing */
typedef int64_t (*xcgi_writer)(struct xcgi_strm *s, const void *buffer, int64_t size);

typedef enum {
    XCGI_STRM_MODE_READ = (1 << 0),
    XCGI_STRM_MODE_WRITE = (1 << 1),
} xcgi_strm_mode;

typedef struct xcgi_fcgi_strm {
    xcgi_strm *strm;
    uint8_t type;
    int fd;
    char *buff;
    size_t buff_size;
} xcgi_fcgi_strm;

xcgi_strm *xcgi_strm_new(xcgi_reader f, void *data);
void xcgi_strm_destroy(xcgi_strm *s);

void *xcgi_strm_udata(xcgi_strm *s);

const void *xcgi_strm_next(xcgi_strm *s, size_t min, int64_t *avail);
int64_t xcgi_strm_consume(xcgi_strm *s, int64_t size);

xcgi_fcgi_strm *xcgi_fcgi_strm_new(xcgi* x, uint8_t type);
void xcgi_fcgi_strm_destroy(xcgi_fcgi_strm *s);