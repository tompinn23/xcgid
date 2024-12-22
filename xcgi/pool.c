#include "xcgi/pool.h"

#include <stdint.h>
#include <stdlib.h>

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
    mpool->data = malloc((object + sizeof(void*)) * num);
    if(!mpool->data) {
        free(mpool);
        return NULL;
    }
    mpool->size = object * num;
    mpool->object = object;

    mpool->free = NULL;
    for(size_t n = 0; n < num; n++) {
        char *entry_ptr = (char *)mpool->data + (object + sizeof(void *)) * n;
        struct xcgi_mpool_entry *entry = (struct xcgi_mpool_entry *)(entry_ptr + sizeof(void *));
        entry->next = mpool->free;
        mpool->free = entry;
        void **pool_ptr = (void **)entry_ptr;
        *pool_ptr = mpool;
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

size_t xcgi_mpool_objsz(xcgi_mpool *mpool) {
    return mpool->object;
}

/**
 * Free an object from the pool.
 * Appending to the beginning of the free list.
 */
void xcgi_mpool_free(void *ptr) {
    if(ptr == NULL) {
        return;
    }
    xcgi_mpool *mpool = *((xcgi_mpool **)((char *)ptr - sizeof(void *)));
    struct xcgi_mpool_entry *entry = (struct xcgi_mpool_entry *)ptr;
    entry->next = mpool->free;
    mpool->free = entry;
}