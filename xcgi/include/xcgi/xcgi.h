#pragma once

#include <stdint.h>

#include "xcgi/pool.h"

#define XCGI_OK (0)
#define XCGI_ERROR (-1)
#define XCGI_MORE (-2)


#define XCGI_MODE_FCGI 1
#define XCGI_MODE_XCGI 2

#define XCGI_LISTENSOCK_ENV "XCGI_LISTENSOCK"

typedef struct xcgi {
  int mode;
  int ctrl, fd;
  uint64_t cookie;

  xcgi_mpool *mpool;
} xcgi;

typedef struct xcgi_request {
  
} xcgi_request;

int xcgi_init(xcgi *x);

int xcgi_accept(xcgi* x);
