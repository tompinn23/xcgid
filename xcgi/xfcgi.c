#include "xcgi/fcgi.h"

#include "xcgi/xcgi.h"
#include "xcgi/endian.h"

#include "utils.h"



int xcgi_read_fcgi_header(void *buffer, size_t bufsize, struct fcgi_header *header) {
    struct fcgi_header h;
    size_t bufptr = 0;
    
    /** if we don't have enough data to read a header immediately request more */
    if(bufsize < sizeof(struct fcgi_header)) {
        return XCGI_MORE;
    }
    
    /** read the header handling endianness */
    h.version = ((uint8_t*)buffer)[bufptr++];
    h.type = ((uint8_t*)buffer)[bufptr++];
    h.request_id = decode_be16(&((uint8_t*)buffer)[bufptr]);
    bufptr += 2;
    h.content_length = decode_be16(&((uint8_t*)buffer)[bufptr]);
    bufptr += 2;
    h.padding_length = ((uint8_t*)buffer)[bufptr++];
    h.reserved = ((uint8_t*)buffer)[bufptr++];

    *header = h;
    return XCGI_OK;
}

int xcgi_read_begin_request(void *buffer, size_t bufsize, struct fcgi_begin_request *record) {
    struct fcgi_begin_request r;
    size_t bufptr = 0;
    int rc = XCGI_OK;
    
    /** if we don't have enough data to read a record immediately request more */
    if(bufsize < sizeof(struct fcgi_begin_request)) {
        return XCGI_MORE;
    }
    
    /** read the record handling endianness */
    if((rc = xcgi_read_fcgi_header(buffer, bufsize, &r.header)) != XCGI_OK) {
        return rc;
    }
    bufptr = sizeof(struct fcgi_header);
    r.role = decode_be16(&((uint8_t*)buffer)[bufptr]);
    bufptr += 2;
    r.flags = ((uint8_t*)buffer)[bufptr++];
    r.reserved[0] = ((uint8_t*)buffer)[bufptr++];
    r.reserved[1] = ((uint8_t*)buffer)[bufptr++];
    r.reserved[2] = ((uint8_t*)buffer)[bufptr++];
    r.reserved[3] = ((uint8_t*)buffer)[bufptr++];
    r.reserved[4] = ((uint8_t*)buffer)[bufptr++];

    *record = r;
    return XCGI_OK;
}

int xcgi_read_end_request(void *buffer, size_t bufsize, struct fcgi_end_request *record) {
    struct fcgi_end_request r;
    size_t bufptr = 0;
    int rc = XCGI_OK;
    
    /** if we don't have enough data to read a record immediately request more */
    if(bufsize < sizeof(struct fcgi_end_request)) {
        return XCGI_MORE;
    }
    
    /** read the record handling endianness */
    if((rc = xcgi_read_fcgi_header(buffer, bufsize, &r.header)) != XCGI_OK) {
        return rc;
    }
    bufptr = sizeof(struct fcgi_header);
    r.app_status[0] = ((uint8_t*)buffer)[bufptr++];
    r.app_status[1] = ((uint8_t*)buffer)[bufptr++];
    r.app_status[2] = ((uint8_t*)buffer)[bufptr++];
    r.app_status[3] = ((uint8_t*)buffer)[bufptr++];
    r.protocol_status = ((uint8_t*)buffer)[bufptr++];
    r.reserved[0] = ((uint8_t*)buffer)[bufptr++];
    r.reserved[1] = ((uint8_t*)buffer)[bufptr++];
    r.reserved[2] = ((uint8_t*)buffer)[bufptr++];

    *record = r;
    return XCGI_OK;
}

static int decode_varint(void *buffer, uint32_t *value) {
    uint8_t *buf = (uint8_t*)buffer;
    if((*buf >> 7) == 1) {
        *value = decode_be32(buffer);
        return 4;
    } else {
        *value = *buf;
        return 1;
    }
}

static int encode_varint(void *buffer, uint32_t value) {
    uint8_t *buf = (uint8_t*)buffer;
    if(value < 128) {
        if(buf != NULL) {
            *buf = value;
        }
        return 1;
    } else {
        if(buf != NULL) {
            encode_be32(buf, value);
        }
        return 4;
    }
}

int xcgi_read_kv(void *buffer, size_t bufsize, struct fcgi_keyvalue *keyvalue) {
    struct fcgi_keyvalue kv;
    size_t bufptr = 0;
    uint32_t keylen = 0;
    uint32_t valuelen = 0;
    int rc = XCGI_OK;
    
    /** if we don't have enough data to read atleast the lengths. */
    if(bufsize < 2) {
        return XCGI_MORE;
    }

    bufptr += decode_varint(buffer + bufptr, &keylen);
    bufptr += decode_varint(buffer + bufptr, &valuelen);

    if(bufsize < bufptr + keylen + valuelen) {
        return XCGI_MORE;
    }

    kv.key = (char*)buffer + bufptr;
    bufptr += keylen;
    kv.value = (char*)buffer + bufptr;
    bufptr += valuelen;

    kv.keylen = keylen;
    kv.valuelen = valuelen; 

    *keyvalue = kv;
    return bufptr;
}

int xcgi_read_kva(void *buffer, size_t bufsize, struct fcgi_keyvalue *kv) {
    struct fcgi_keyvalue kva;
    int rc = 0;

    if((rc = xcgi_read_kv(buffer, bufsize, &kva)) < 0) {
        return rc;
    }

    kv->keylen = kva.keylen;
    kv->valuelen = kva.valuelen;
    kv->key = xstrndup(kva.key, kva.keylen);
    kv->value = xstrndup(kva.value, kva.valuelen);

    return XCGI_OK;
}

/*  you MUST pass a buffer of atleast 8 bytes */
int64_t xcgi_kv_size(const void *buffer) {
    uint32_t keylen = 0;
    uint32_t valuelen = 0;
    size_t bufptr = 0;
    
    bufptr += decode_varint(buffer + bufptr, &keylen);
    bufptr += decode_varint(buffer + bufptr, &valuelen);

    return bufptr + keylen + valuelen;   
}

/*
* Writing functions
*/

int xcgi_write_fcgi_header(void *buffer, size_t bufsize, struct fcgi_header *header) {
    struct fcgi_header h;
    size_t bufptr = 0;
    
    /** if we don't have enough data to write a header immediately request more */
    if(bufsize < sizeof(struct fcgi_header)) {
        return XCGI_MORE;
    }
    
    /** write the header handling endianness */
    h.version = header->version;
    h.type = header->type;
    encode_be16(&((uint8_t*)buffer)[bufptr], header->request_id);
    bufptr += 2;
    encode_be16(&((uint8_t*)buffer)[bufptr], header->content_length);
    bufptr += 2;
    ((uint8_t*)buffer)[bufptr++] = header->padding_length;
    ((uint8_t*)buffer)[bufptr++] = header->reserved;

    return XCGI_OK;
}

int xcgi_write_begin_request(void *buffer, size_t bufsize, struct fcgi_begin_request *record) {
    struct fcgi_begin_request r;
    size_t bufptr = 0;
    int rc = XCGI_OK;
    
    /** if we don't have enough data to write a record immediately request more */
    if(bufsize < sizeof(struct fcgi_begin_request)) {
        return XCGI_MORE;
    }
    
    /** write the record handling endianness */
    if((rc = xcgi_write_fcgi_header(buffer, bufsize, &record->header)) != XCGI_OK) {
        return rc;
    }
    bufptr = sizeof(struct fcgi_header);
    encode_be16(&((uint8_t*)buffer)[bufptr], record->role);
    bufptr += 2;
    ((uint8_t*)buffer)[bufptr++] = record->flags;
    ((uint8_t*)buffer)[bufptr++] = record->reserved[0];
    ((uint8_t*)buffer)[bufptr++] = record->reserved[1];
    ((uint8_t*)buffer)[bufptr++] = record->reserved[2];
    ((uint8_t*)buffer)[bufptr++] = record->reserved[3];
    ((uint8_t*)buffer)[bufptr++] = record->reserved[4];

    return XCGI_OK;
}

int xcgi_write_end_request(void *buffer, size_t bufsize, struct fcgi_end_request *record) {
    struct fcgi_end_request r;
    size_t bufptr = 0;
    int rc = XCGI_OK;
    
    /** if we don't have enough data to write a record immediately request more */
    if(bufsize < sizeof(struct fcgi_end_request)) {
        return XCGI_MORE;
    }
    
    /** write the record handling endianness */
    if((rc = xcgi_write_fcgi_header(buffer, bufsize, &record->header)) != XCGI_OK) {
        return rc;
    }
    bufptr = sizeof(struct fcgi_header);
    ((uint8_t*)buffer)[bufptr++] = record->app_status[0];
    ((uint8_t*)buffer)[bufptr++] = record->app_status[1];
    ((uint8_t*)buffer)[bufptr++] = record->app_status[2];
    ((uint8_t*)buffer)[bufptr++] = record->app_status[3];
    ((uint8_t*)buffer)[bufptr++] = record->protocol_status;
    ((uint8_t*)buffer)[bufptr++] = record->reserved[0];
    ((uint8_t*)buffer)[bufptr++] = record->reserved[1];
    ((uint8_t*)buffer)[bufptr++] = record->reserved[2];

    return XCGI_OK;
}


int xcgi_write_kv(void *buffer, size_t bufsize, struct fcgi_keyvalue *kv) {
    size_t bufptr = 0;
    
    /** calculate the size of varints */
    bufptr += encode_varint(NULL, kv->keylen);
    bufptr += encode_varint(NULL, kv->valuelen);

    /** if we don't have enough data to write atleast the lengths. */
    if(bufsize < bufptr + kv->keylen + kv->valuelen) {
        return XCGI_MORE;
    }

    bufptr = 0;
    bufptr += encode_varint(buffer + bufptr, kv->keylen);
    bufptr += encode_varint(buffer + bufptr, kv->valuelen);
    
    memcpy(buffer + bufptr, kv->key, kv->keylen);
    bufptr += kv->keylen;
    memcpy(buffer + bufptr, kv->value, kv->valuelen);
    bufptr += kv->valuelen;

    return XCGI_OK;
}


