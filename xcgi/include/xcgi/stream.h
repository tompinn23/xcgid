#pragma once

#include "xcgi/pool.h"

#include <stddef.h>

#include <stdint.h>

typedef struct xcgi_strm xcgi_strm;

typedef int64_t (*xcgi_filler)(struct xcgi_strm *s, const void **buffer);

struct xcgi_strm {
    void        *data;
    xcgi_filler filler;

    char		*buffer;
	size_t		 buffer_size;
    char		*next;		/* Current read location. */
	size_t		 avail;		/* Bytes in my buffer. */
	const void	*client_buff;	/* Client buffer information. */
	size_t		 client_total;
	const char	*client_next;
	size_t		 client_avail;

    int eof;
    int fatal;
};

xcgi_strm *xcgi_strm_new(xcgi_filler f, void *data);
void xcgi_strm_destroy(xcgi_strm *s);

const void *xcgi_strm_next(xcgi_strm *s, size_t min, int64_t *avail);
int64_t xcgi_strm_consume(xcgi_strm *s, int64_t size);