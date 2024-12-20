#ifndef FCGI_H
#define FCGI_H

#include <stdint.h>

#define FCGI_VERSION_1 1

#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)

struct fcgi_header {
    uint8_t version;
    uint8_t type;
    uint16_t request_id;
    uint16_t content_length;
    uint8_t padding_length;
    uint8_t reserved;
};

struct fcgi_record {
    struct fcgi_header header;
    uint8_t *content;
};

struct fcgi_begin_request {
    struct fcgi_header header;
    uint16_t role;
    uint8_t flags;
    uint8_t reserved[5];
};

struct fcgi_end_request {
    struct fcgi_header header;
    uint8_t app_status[4];
    uint8_t protocol_status;
    uint8_t reserved[3];
};

struct fcgi_keyvalue {
    uint32_t keylen;
    uint32_t valuelen;
    char *key;
    char *value;
};

/**
 * Decode a fcgi key value pair from a buffer.
 */
int xcgi_read_kv(void *buffer, size_t bufsize, struct fcgi_keyvalue *keyvalue);
/**
 * Decode a fcgi key value pair from a buffer but allocate new memory so the original buffer can disappear.
 */
int xcgi_read_kva(void *buffer, size_t bufsize, struct fcgi_keyvalue *keyvalue);

#endif
