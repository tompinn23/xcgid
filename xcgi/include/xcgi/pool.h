#pragma once

#include <stddef.h>

struct xcgi_mpool_entry;

typedef struct xcgi_mpool {
    void *data;
    size_t size;
    size_t object;
    struct xcgi_mpool_entry *free;
} xcgi_mpool;

xcgi_mpool *xcgi_mpool_create(size_t object, size_t num);
void xcgi_mpool_destroy(xcgi_mpool *mpool);
void *xcgi_mpool_alloc(xcgi_mpool *mpool);
void xcgi_mpool_free(xcgi_mpool *mpool, void *ptr);
size_t xcgi_mpool_objsz(xcgi_mpool *mpool);