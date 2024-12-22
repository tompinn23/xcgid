#include "xcgi/stream.h"

#include "xcgi/xcgi.h"
#include "xcgi/fcgi.h"

#include <stdlib.h>
#include <string.h>

#define XCGI_STRM_BUFFSIZE 8192

struct xcgi_strm {
    void        *data;
    xcgi_reader reader;
    xcgi_writer writer;

    char		*buffer;
	size_t		 buffer_size;
    char		*next;		/* Current read location. */
	size_t		 avail;		/* Bytes in my buffer. */
	const void	*client_buff;	/* Client buffer information. */
	size_t		 client_total;
	const char	*client_next;
	size_t		 client_avail;

    int flags;

    int eof;
    int fatal;
};

xcgi_strm *xcgi_strm_reader(xcgi_reader f, void *data) {
    return xcgi_strm_new(f, NULL, data, XCGI_STRM_MODE_READ);
}

xcgi_strm *xcgi_strm_new(xcgi_reader f, xcgi_writer w, void *data, int flags) {
    if(flags & XCGI_STRM_MODE_READ) {
        if(!f) {
            return NULL;
        }
    } else if(flags & XCGI_STRM_MODE_WRITE) {
        if(!w) {
            return NULL;
        }
    } else if(flags & XCGI_STRM_MODE_READ | XCGI_STRM_MODE_WRITE) {
        return NULL;
    }

    xcgi_strm *s = calloc(1, sizeof(xcgi_strm));
    if(!s) {
        return NULL;
    }
    s->reader = f;
    s->writer = w;
    s->flags = flags;
    s->data = data;
    return s;
}

void *xcgi_strm_udata(xcgi_strm *s) {
    return s->data;
}

void xcgi_strm_destroy(xcgi_strm *s) {
    if(!s) { return; }
    free(s->buffer);
    free(s);
}

const void *xcgi_strm_next(xcgi_strm *s, size_t min, int64_t *avail) {
    if(s->fatal || !(s->flags & XCGI_STRM_MODE_READ) || s->eof) {
        return NULL;
    }

    int64_t bytes_read;
    size_t tocopy;

    for(;;) {
        /* if we have enough in the copy buffer fulfil request directly.*/
        if(s->avail >= min) {
            if(avail) {
                *avail = s->avail;
            }
            return s->next;
        }

		/*
		 * We can satisfy directly from client buffer if everything
		 * currently in the copy buffer is still in the client buffer.
		 */
        if(s->client_total >= s->client_avail + s->avail && s->client_avail + s->avail >= min) {
            s->client_avail += s->avail;
            s->client_next -= s->avail;

            /* copy buffer is empty */
            s->avail = 0;
            s->next = s->buffer;

            if(avail) {
                *avail = s->client_avail;
            }
            return s->client_next;
        }

		/* Move data forward in copy buffer if necessary. */
        if(s->next > s->buffer && s->next + min > s->buffer + s->buffer_size) {
            if(s->avail > 0) {
                memmove(s->buffer, s->next, s->avail);
                s->next = s->buffer;
            }
        }

        /* if we have used up client data get more */
        if(s->client_avail <= 0) {
            if(s->eof) {
                if(avail) {
                    *avail = s->avail;
                }
                return NULL;
            }
            bytes_read = s->reader(s, &s->client_buff);
            if(bytes_read < 0) { /* read error */
                s->client_total = s->client_avail = 0;
                s->client_next = s->client_buff = NULL;
                s->fatal = 1;
                if(avail) {
                    *avail = (-1);
                }
                return NULL;
            }
            if(bytes_read == 0) {
                s->eof = 1;
                s->client_total = s->client_avail = 0;
				s->client_next =
				    s->client_buff = NULL;
                if(avail) {
                    *avail = s->avail;
                }
                return NULL;
            }
            s->client_total = bytes_read;
            s->client_avail = s->client_total;
            s->client_next = s->client_buff;
        } else {
            /*
			 * We can't satisfy the request from the copy
			 * buffer or the existing client data, so we
			 * need to copy more client data over to the
			 * copy buffer.
			 */

            if(min > s->buffer_size) {
                size_t n, t;
                char *p;

                n = t = s->buffer_size;
                if(n == 0) {
                    n = min;
                }
                while(n < min) {
                    t *= 2;
                    if(t <= n) {
                        s->fatal = 1;
                        if(avail) {
                            *avail = (-1);
                        }
                        return NULL;
                    }
                    n = t;
                }
                p = malloc(n);
                if(p == NULL) {
                    s->fatal = 1;
                    if(avail) {
                        *avail = (-1);
                    }
                    return NULL;
                }
                if(s->avail > 0) {
                    memmove(p, s->next, s->avail);
                }
                free(s->buffer);
                s->next = s->buffer = p;
                s->buffer_size = n;
            }

            tocopy = (s->buffer + s->buffer_size) - (s->next + s->avail);
            if(tocopy + s->avail > min) {
                tocopy = min - s->avail;
            }
            if(tocopy > s->client_avail) {
                tocopy = s->client_avail;
            }
            memcpy(s->next + s->avail, s->client_next, tocopy);
            s->client_next += tocopy;
            s->client_avail -= tocopy;
            s->avail += tocopy;
        }
    }
}

static inline int64_t i64_min(int64_t a, int64_t b) {
    return a < b ? a : b;
}

static int64_t advance_stream(xcgi_strm *s, int64_t request) {
    int64_t bytes_skipped, total_bytes_skipped = 0;
	int64_t bytes_read;
	int64_t min;

    if(s->fatal) {
        return -1;
    }

    if(s->avail > 0) {
        min = i64_min(request, s->avail);
        s->next += min;
        s->avail -= min;
        request -= min;
        total_bytes_skipped += min;
    }

    if(s->client_avail > 0) {
        min = i64_min(request, s->client_avail);
        s->client_next += min;
        s->client_avail -= min;
        request -= min;
        total_bytes_skipped += min;
    }

    if(request == 0) {
        return total_bytes_skipped;
    }

    for(;;) {
        bytes_read = s->reader(s, &s->client_buff);
        if(bytes_read < 0) {
            s->client_buff = NULL;
            s->fatal = 1;
            return bytes_read;
        }

        if(bytes_read == 0) {
            s->client_buff = NULL;
            s->eof = 1;
            return total_bytes_skipped;
        }

        if(bytes_read >= request) {
            s->client_next = ((const char *)s->client_buff) + request;
            s->client_avail = bytes_read - request;
            s->client_total = bytes_read;
            total_bytes_skipped += request;
            return total_bytes_skipped;
        }

        total_bytes_skipped += bytes_read;
        request -= bytes_read;
    }
}

int64_t xcgi_strm_consume(xcgi_strm *s, int64_t request) {
    if(s->fatal || !(s->flags & XCGI_STRM_MODE_READ)) {
        return -1;
    }

    int64_t skipped;
    if(request < 0) {
        return -1;
    }
    if(request == 0) {
        return 0;
    }

    skipped = advance_stream(s, request);
    if(skipped == request) {
        return skipped;
    }

    return -1;
}

/** writer functions */

int64_t xcgi_strm_write(xcgi_strm *s, const void *buffer, size_t size) {
    if(buffer == NULL || size == 0) {
        return 0;
    }

    if(s->fatal || !(s->flags & XCGI_STRM_MODE_WRITE)) {
        return -1;
    }

    int64_t rc;

    int64_t total_bytes_written = 0;


    if(s->buffer_size == 0) {
        s->buffer_size = s->writer(s, NULL, -1);
        if(s->buffer_size < 0) {
            s->fatal = 1;
            return -1;
        }
        s->buffer = malloc(s->buffer_size);
        if(!s->buffer) {
            s->fatal = 1;
            return -1;
        }
        s->next = s->buffer;
        s->avail = s->buffer_size;
    }

    for(;;) {
        if(size == 0) {
            break;
        }
        /* if the buffer is empty and we have more than a buffers worth send it immediately. */
        if(size >= s->buffer_size && s->avail == s->buffer_size) {
            if((rc = s->writer(s, s->buffer, s->buffer_size)) <= 0) {
                s->fatal = 1;
                return -1;
            }
            total_bytes_written += rc;
            size -= rc;
            buffer += rc;
        }

        /* if there is space in the buffer copy it in. */
        if(s->avail >= size) {
            memcpy(s->next, buffer, size);
            s->next += size;
            s->avail -= size;
            total_bytes_written += size;
            break;
        }

        /* copy what we can then flush to writer then copy rest.*/
        if(s->avail > 0) {
            memcpy(s->next, buffer, s->avail);
            buffer += s->avail;
            size -= s->avail;
            total_bytes_written += s->avail;
            s->next += s->avail;
            s->avail = 0;
        }

        /* buffer full flush */
        if(s->avail == 0) {
            if((rc = s->writer(s, s->buffer, s->buffer_size)) <= 0) {
                s->fatal = 1;
                return -1;
            }
            if(rc == s->buffer_size) {
                s->next = s->buffer;
                s->avail = s->buffer_size;
            } else {
                /* move data forward */
                memmove(s->buffer, s->buffer + rc, s->buffer_size - rc);
                s->next = s->buffer + (s->buffer_size - rc);
                s->avail = rc;
            }
        }
    }

    return total_bytes_written;
}

int64_t xcgi_strm_flush(xcgi_strm *s) {
    if(s->fatal || !(s->flags & XCGI_STRM_MODE_WRITE)) {
        return -1;
    }

    if(s->avail == s->buffer_size) {
        return 0;
    }

    int64_t rc;
    if((rc = s->writer(s, s->buffer, s->buffer_size - s->avail)) <= 0) {
        s->fatal = 1;
        return -1;
    } else if(rc != s->buffer_size - s->avail) {
        s->fatal = 1;
        return -1;
    } else {
        s->next = s->buffer;
        s->avail = s->buffer_size;
    }
    return rc;
}

static int64_t filler(xcgi_strm *s, const void **buffer) {
    fcgi_header hdr;
    char hdr_buf[FCGI_HEADER_LEN];
    int rc;

    xcgi_fcgi_strm *ctx = s->data;

    /** read the header data */
    if(!xfullread(ctx->fd, 0, hdr_buf, FCGI_HEADER_LEN)) {
        return -1;
    }

    /* parse the header into a structure */
    if(xcgi_read_fcgi_header(hdr_buf, FCGI_HEADER_LEN, &hdr) != XCGI_OK) {
        return -1;
    }
    
    /* if it's not the type we want error */
    if(hdr.type != ctx->type) {
        return -1;
    }

    /* if theres no data we are eof */
    if(hdr.content_length == 0) {
        return 0;
    }

    /* if this happens something has broken fcgi spec */
    if(hdr.content_length > ctx->buff_size) {
        return -1;
    }

    /* read the content */
    if(!xfullread(ctx->fd, 0, ctx->buff, hdr.content_length)) {
        return -1;
    }

    /* discard padding */
    if(!xreaddiscard(ctx->fd, hdr.padding_length)) {
        return -1;
    }

    *buffer = ctx->buff;  
    return hdr.content_length;
}

xcgi_fcgi_strm *xcgi_fcgi_strm_new(xcgi* x, uint8_t type) {
    xcgi_fcgi_strm *s = calloc(1, sizeof(xcgi_fcgi_strm));
    if(!s) {
        return NULL;
    }
    s->strm = xcgi_strm_new(filler, NULL, s, XCGI_STRM_MODE_READ);
    s->buff = xcgi_mpool_alloc(x->mpool);
    if(!s->strm || !s->buff) {
        xcgi_fcgi_strm_destroy(s);
        return NULL;
    }
    s->buff_size = xcgi_mpool_objsz(x->mpool);
    s->type = type;
    s->fd = x->fd;
    return s;
}
void xcgi_fcgi_strm_destroy(xcgi_fcgi_strm *s) {
    if(!s) { return; }
    xcgi_strm_destroy(s->strm);
    xcgi_mpool_free(s->buff);
    free(s);
}


