#include "xcgi/stream.h"

#include <stdlib.h>
#include <string.h>

#define XCGI_STRM_BUFFSIZE 8192

xcgi_strm *xcgi_strm_new(xcgi_filler f, void *data) {
    xcgi_strm *s = calloc(1, sizeof(xcgi_strm));
    if(!s) {
        return NULL;
    }
    s->filler = f;
    s->data = data;
    return s;
}

void xcgi_strm_destroy(xcgi_strm *s) {
    if(!s) { return; }
    free(s->buffer);
    free(s);
}

const void *xcgi_strm_next(xcgi_strm *s, size_t min, int64_t *avail) {
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
            bytes_read = s->filler(s, &s->client_buff);
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
        bytes_read = s->filler(s, &s->client_buff);
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

