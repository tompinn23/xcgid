#pragma once

#include <stdint.h>

typedef struct xcgi xcgi;
typedef struct sc_map_str sc_map_str;

typedef struct xcgi_req {
    int id;
    sc_map_str *params;
} xcgi_req;

typedef struct xcgi_req_iter {
    xcgi_req *req;
    int64_t _i;
    int64_t _b;
} xcgi_req_iter;

int xcgi_read_params(xcgi *x, xcgi_req *req);
int xcgi_request(xcgi *x, xcgi_req *req);

int xcgi_request_params_iter(xcgi_req_iter *iter, xcgi_req *req);
int xcgi_request_params_next(xcgi_req_iter *iter, char **key, char **value);
