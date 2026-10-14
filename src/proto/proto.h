#ifndef CTF_PROTO_H
#define CTF_PROTO_H

/*
 * PROTO - custom framing protocol used between the WEB and LOGIC servers.
 *
 * Wire format
 * -----------
 *   +---------------------------+
 *   | magic    : uint16 (BE)    |  always PROTO_MAGIC
 *   | version  : uint8          |  always PROTO_VERSION
 *   | type     : uint8          |  one of enum proto_type
 *   | length   : uint32 (BE)    |  size of the TLV payload
 *   +---------------------------+
 *   | payload  : TLV fields     |
 *   +---------------------------+
 *
 * The payload is a flat sequence of type-length-value fields:
 *   tag : uint32 (BE)
 *   len : uint32 (BE)
 *   val : len raw bytes
 *
 * The protocol is intentionally small, binary and extensible.  Adding a
 * new field never breaks older peers; adding a new message type is a
 * matter of extending the enum.
 *
 * Transport is a persistent, full duplex TCP connection.  The web server
 * is the client, the logic server the listener.  Because every message is
 * length prefixed a single connection can carry any number of in-flight
 * calculations: the logic server answers later with the request id that
 * the web server originally supplied (the "remember this request?" flow).
 */

#include <stddef.h>
#include <stdint.h>

#include "common/util.h"
#include "config.h"

/* ------------------------------------------------------------------ */
/* Framing constants                                                   */
/* ------------------------------------------------------------------ */

#define PROTO_MAGIC   0x4354u /* "CT" */
#define PROTO_VERSION CTF_PROTO_VERSION
#define PROTO_HDR_LEN 8u

/* ------------------------------------------------------------------ */
/* Message types                                                       */
/* ------------------------------------------------------------------ */

typedef enum {
    PROTO_HELLO     = 1, /* web  -> logic : version handshake           */
    PROTO_HELLO_ACK = 2, /* logic-> web   : handshake accepted          */
    PROTO_CALC_REQ  = 3, /* web  -> logic : please crack this           */
    PROTO_CALC_RES  = 4, /* logic-> web   : here is a result you asked  */
    PROTO_PING      = 5,
    PROTO_PONG      = 6,
    PROTO_ERROR     = 7,
    PROTO_BYE       = 8,
    PROTO_ALGO_LIST     = 9,  /* web  -> logic : what can you crack?  */
    PROTO_ALGO_LIST_RES = 10  /* logic-> web   : registry dump        */
} proto_type_t;

/* ------------------------------------------------------------------ */
/* TLV tags                                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    PROTO_TAG_REQ_ID   = 1, /* uint64  correlation id                 */
    PROTO_TAG_ALGO     = 2, /* uint32  algorithm id                   */
    PROTO_TAG_INPUT    = 3, /* bytes   data to operate on             */
    PROTO_TAG_KEY_LEN  = 4, /* uint32  requested key length           */
    PROTO_TAG_FLAGS    = 5, /* uint32  algorithm specific flags       */
    PROTO_TAG_STATUS   = 6, /* uint32  proto_status_t                 */
    PROTO_TAG_RESULT   = 7, /* bytes   UTF-8 result text              */
    PROTO_TAG_ERROR    = 8, /* bytes   human readable error           */
    PROTO_TAG_MESSAGE  = 9, /* bytes   plain UTF-8 message            */
    PROTO_TAG_VERSION  = 10,/* uint32  protocol version               */
    PROTO_TAG_ALGO_NAME = 11,/* bytes  algorithm name                 */
    PROTO_TAG_ALGO_DESC = 12 /* bytes  algorithm description          */
} proto_tag_t;

typedef enum {
    PROTO_STATUS_OK      = 0,
    PROTO_STATUS_ERROR   = 1,
    PROTO_STATUS_PENDING = 2
} proto_status_t;

/* ------------------------------------------------------------------ */
/* In-memory message                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t type;
    buf_t   payload; /* concatenated TLV fields */
} proto_msg_t;

proto_msg_t *proto_msg_new(uint8_t type);
void         proto_msg_free(proto_msg_t *m);

/* Field builders.  All values are stored in network byte order. */
int proto_add(proto_msg_t *m, uint32_t tag, const void *data, uint32_t len);
int proto_add_u32(proto_msg_t *m, uint32_t tag, uint32_t value);
int proto_add_u64(proto_msg_t *m, uint32_t tag, uint64_t value);
int proto_add_str(proto_msg_t *m, uint32_t tag, const char *str);

/* Field accessors.  Returned pointers alias the message buffer. */
const void *proto_get(const proto_msg_t *m, uint32_t tag, uint32_t *len);
int         proto_get_u32(const proto_msg_t *m, uint32_t tag, uint32_t *value);
int         proto_get_u64(const proto_msg_t *m, uint32_t tag, uint64_t *value);
const char *proto_get_str(const proto_msg_t *m, uint32_t tag);

/* Sequential TLV cursor.  Lets a receiver walk repeated fields in order,
 * which is how grouped records (e.g. the algorithm registry) are encoded. */
typedef struct {
    const proto_msg_t *msg;
    size_t             off;
} proto_iter_t;

void proto_iter_init(proto_iter_t *it, const proto_msg_t *m);
/* Returns 1 on a field, 0 when exhausted. */
int proto_iter_next(proto_iter_t *it, uint32_t *tag, const void **val,
                    uint32_t *len);

/* ------------------------------------------------------------------ */
/* Transport                                                           */
/* ------------------------------------------------------------------ */

/* Blocking, full-message send/recv.  Return 0 on success, -1 on failure
 * (including EOF).  proto_recv allocates *out which the caller frees. */
int proto_send(int fd, const proto_msg_t *m);
int proto_recv(int fd, proto_msg_t **out);

const char *proto_type_name(uint8_t type);

#endif /* CTF_PROTO_H */
