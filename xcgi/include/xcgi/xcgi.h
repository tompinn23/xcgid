#pragma once

#include <stdint.h>

#include "xcgi/pool.h"
#include "xcgi/request.h"
#include "xcgi/stream.h"
#include "xcgi/status.h"




#define XCGI_MODE_FCGI 1
#define XCGI_MODE_XCGI 2

#define XCGI_LISTENSOCK_ENV "XCGI_LISTENSOCK"
#define XCGI_INFOSOCK_ENV "XCGI_INFOSOCK"


typedef struct xcgi {
  int mode;
  int ctrl, fd, info;
  uint64_t cookie;

  xcgi_mpool *mpool;
} xcgi;



int xcgi_init(xcgi *x);
int xcgi_info(xcgi *x, const char *s);

int xcgi_accept(xcgi* x);
