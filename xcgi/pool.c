#include "xcgi/pool.h"

#include <stdint.h>

struct xcgi_mpool_entry {
    struct xcgi_mpool_entry *next;
};

xcgi_mpool *xcgi_mpool_create(size_t object, size_t num) {
    if (object != 0 && num > SIZE_MAX / object) {
        return NULL; // Overflow detected
    }
    xcgi_mpool *mpool = malloc(sizeof(xcgi_mpool));
    if(!mpool) {
        return NULL;
    }
    mpool->data = malloc(object * num);
    if(!mpool->data) {
        free(mpool);
        return NULL;
    }
    mpool->size = object * num;
    mpool->object = object;

    mpool->free = NULL;
    for(size_t n = 0; n < num; n++) {
        struct xcgi_mpool_entry *entry = (struct xcgi_mpool_entry *)((char *)mpool->data + (object * n));
        entry->next = mpool->free;
        mpool->free = entry;
    }
    return mpool;
}

void xcgi_mpool_destroy(xcgi_mpool *mpool) {
    free(mpool->data);
    free(mpool);
}

void *xcgi_mpool_alloc(xcgi_mpool *mpool) {
    if(mpool->free == NULL) {
        return NULL;
    }
    struct xcgi_mpool_entry *entry = mpool->free;
    mpool->free = entry->next;
    return entry;
}

/**
 * Free an object from the pool.
 * Appending to the beginning of the free list.
 */
void xcgi_mpool_free(xcgi_mpool *mpool, void *ptr) {
    struct xcgi_mpool_entry *entry = (struct xcgi_mpool_entry *)ptr;
    entry->next = mpool->free;
    mpool->free = entry;
}