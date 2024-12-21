#include "xcgi/request.h"

#include "xcgi/xcgi.h"
#include "xcgi/stream.h"
#include "xcgi/fcgi.h"

#include "utils.h"

#include "sc_map.h"

int xcgi_request(xcgi *x, xcgi_req *req) {
  char *buf = xcgi_mpool_alloc(x->mpool);

  char req_buf[sizeof(struct fcgi_begin_request)];
  if(!xfullread(x->fd, 0, req_buf, sizeof(req_buf))) {
    return -1;
  }

  struct fcgi_begin_request begin_request;
  if(xcgi_read_begin_request(req_buf, sizeof(req_buf), &begin_request) != XCGI_OK) {
    return -1;
  }

  req->id = begin_request.header.request_id;

  if(!xcgi_read_params(x, req)) {
    return -1;
  }
}

typedef struct filler_ctx {
    uint8_t type;
    int fd;
    char *buff;
    size_t buff_size;
} filler_ctx;


static int64_t filler(xcgi_strm *s, const void **buffer) {
    fcgi_header hdr;
    char hdr_buf[FCGI_HEADER_LEN];
    int rc;

    filler_ctx *ctx = s->data;

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


int xcgi_read_params(xcgi *x, xcgi_req *req) {
    filler_ctx           ctx;
    xcgi_strm            *s;
    const void           *data;
    struct fcgi_keyvalue kv;
    int                  exit = 0;

    ctx.buff = NULL;

    if(req->params == NULL) {
        req->params = calloc(1, sizeof(sc_map_str));
        if(req->params == NULL) {
            exit = -1;
            goto out;
        }
        if(!sc_map_init_str(req->params, 0, 0)) {
            exit = -1;
            goto out;
        }
    }   

    ctx.type = FCGI_PARAMS;
    ctx.buff = xcgi_mpool_alloc(x->mpool);
    ctx.buff_size = xcgi_mpool_objsz(x->mpool);
    s = xcgi_strm_new(filler, &ctx);
    if(!s) {
        exit = -1;
        goto out;
    }

    
    for(;;) {
        kv.key = NULL;
        kv.value = NULL;
        /** give me 8 bytes this is enough to fully read the keyvalue lengths */
        data = xcgi_strm_next(s, 8, NULL);
        if(data == NULL) {        
            exit = -1;
            goto out;
        }
        /* pass those 8 bytes to the size function to calculate the total length of the keyvalue pair*/
        int64_t buffsize = xcgi_kv_size(data);
        data = xcgi_strm_next(s, buffsize, NULL);
        if(data == NULL) {
            exit = -1;
            goto out;
        }
        /* read the keyvalue pair */
        if(xcgi_read_kva(data, buffsize, &kv) != XCGI_OK) {
            exit = -1;
            goto out;
        }
        if(xcgi_strm_consume(s, buffsize) != buffsize) {
            exit = -1;
            goto out;
        }
        sc_map_put_str(req->params, kv.key, kv.value);
    }

out:
    free(kv.key);
    free(kv.value);
    xcgi_strm_destroy(s);
    xcgi_mpool_free(x->mpool, ctx.buff);
    return exit;
}

int xcgi_request_params_iter(xcgi_req_iter *iter, xcgi_req *req) {
    iter->req = req;
    iter->_i = -1;
    iter->_b = 0;
    return 0;
}
int xcgi_request_params_next(xcgi_req_iter *iter, char **key, char **value) {
    for(; !iter->_b && iter->_i < iter->req->params->cap; iter->_i++) {
        for((*value) = iter->req->params->mem[iter->_i].value, (*key) = iter->req->params->mem[iter->_i].key, iter->_b = 1;
            iter->_b && ((iter->_i == -1 && iter->req->params->used) || (*key) != 0) ? 1 : (iter->_b = 0);
            iter->_b = 0) {
                return 1;
            }
    }
    return 0;
}