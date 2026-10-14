#define _GNU_SOURCE
#include "proto/proto.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Message lifecycle                                                   */
/* ------------------------------------------------------------------ */

proto_msg_t *proto_msg_new(uint8_t type)
{
    proto_msg_t *m = calloc(1, sizeof *m);
    if (!m)
        return NULL;
    m->type = type;
    buf_init(&m->payload);
    return m;
}

void proto_msg_free(proto_msg_t *m)
{
    if (!m)
        return;
    buf_free(&m->payload);
    free(m);
}

/* ------------------------------------------------------------------ */
/* Field builders                                                      */
/* ------------------------------------------------------------------ */

int proto_add(proto_msg_t *m, uint32_t tag, const void *data, uint32_t len)
{
    uint32_t be_tag = htonl(tag);
    uint32_t be_len = htonl(len);
    if (buf_append(&m->payload, &be_tag, sizeof be_tag) != 0)
        return -1;
    if (buf_append(&m->payload, &be_len, sizeof be_len) != 0)
        return -1;
    if (len && buf_append(&m->payload, data, len) != 0)
        return -1;
    return 0;
}

int proto_add_u32(proto_msg_t *m, uint32_t tag, uint32_t value)
{
    uint32_t be = htonl(value);
    return proto_add(m, tag, &be, sizeof be);
}

int proto_add_u64(proto_msg_t *m, uint32_t tag, uint64_t value)
{
    uint64_t be = htobe64(value);
    return proto_add(m, tag, &be, sizeof be);
}

int proto_add_str(proto_msg_t *m, uint32_t tag, const char *str)
{
    /* Text fields carry a trailing NUL so that proto_get_str() is safe
     * to use directly on the receiver side. */
    return proto_add(m, tag, str, (uint32_t)strlen(str) + 1);
}

/* ------------------------------------------------------------------ */
/* Field accessors                                                     */
/* ------------------------------------------------------------------ */

const void *proto_get(const proto_msg_t *m, uint32_t tag, uint32_t *len)
{
    size_t off = 0;
    while (off + 8 <= m->payload.len) {
        uint32_t t, l;
        memcpy(&t, m->payload.data + off, sizeof t);
        memcpy(&l, m->payload.data + off + 4, sizeof l);
        t = ntohl(t);
        l = ntohl(l);
        off += 8;
        if (off + l > m->payload.len)
            return NULL; /* malformed */
        if (t == tag) {
            if (len)
                *len = l;
            return m->payload.data + off;
        }
        off += l;
    }
    return NULL;
}

int proto_get_u32(const proto_msg_t *m, uint32_t tag, uint32_t *value)
{
    uint32_t len = 0;
    const void *p = proto_get(m, tag, &len);
    if (!p || len != sizeof(uint32_t))
        return -1;
    uint32_t be;
    memcpy(&be, p, sizeof be);
    *value = ntohl(be);
    return 0;
}

int proto_get_u64(const proto_msg_t *m, uint32_t tag, uint64_t *value)
{
    uint32_t len = 0;
    const void *p = proto_get(m, tag, &len);
    if (!p || len != sizeof(uint64_t))
        return -1;
    uint64_t be;
    memcpy(&be, p, sizeof be);
    *value = be64toh(be);
    return 0;
}

const char *proto_get_str(const proto_msg_t *m, uint32_t tag)
{
    uint32_t len = 0;
    const void *p = proto_get(m, tag, &len);
    if (!p)
        return NULL;
    /* The protocol never guarantees NUL termination, so callers must use
     * proto_get() with an explicit length when the value may be binary.
     * Text fields produced by this project are always NUL padded by the
     * sender (buf_append_cstr), so this is safe for them. */
    return (const char *)p;
}

void proto_iter_init(proto_iter_t *it, const proto_msg_t *m)
{
    it->msg = m;
    it->off = 0;
}

int proto_iter_next(proto_iter_t *it, uint32_t *tag, const void **val,
                    uint32_t *len)
{
    const proto_msg_t *m = it->msg;
    if (it->off + 8 > m->payload.len)
        return 0;
    uint32_t t, l;
    memcpy(&t, m->payload.data + it->off, sizeof t);
    memcpy(&l, m->payload.data + it->off + 4, sizeof l);
    t = ntohl(t);
    l = ntohl(l);
    it->off += 8;
    if (it->off + l > m->payload.len)
        return 0;
    if (tag)
        *tag = t;
    if (val)
        *val = m->payload.data + it->off;
    if (len)
        *len = l;
    it->off += l;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Transport                                                           */
/* ------------------------------------------------------------------ */

int proto_send(int fd, const proto_msg_t *m)
{
    if (m->payload.len > CTF_PROTO_MAX_PAYLOAD)
        return -1;

    uint8_t hdr[PROTO_HDR_LEN];
    uint16_t magic = htons(PROTO_MAGIC);
    uint8_t  version = PROTO_VERSION;
    uint8_t  type = m->type;
    uint32_t len = htonl((uint32_t)m->payload.len);

    memcpy(hdr + 0, &magic, 2);
    memcpy(hdr + 2, &version, 1);
    memcpy(hdr + 3, &type, 1);
    memcpy(hdr + 4, &len, 4);

    if (fd_write_full(fd, hdr, sizeof hdr) != 0)
        return -1;
    if (m->payload.len && fd_write_full(fd, m->payload.data, m->payload.len) != 0)
        return -1;
    return 0;
}

int proto_recv(int fd, proto_msg_t **out)
{
    uint8_t hdr[PROTO_HDR_LEN];
    if (fd_read_full(fd, hdr, sizeof hdr) != 0)
        return -1;

    uint16_t magic;
    uint32_t len;
    memcpy(&magic, hdr + 0, 2);
    memcpy(&len, hdr + 4, 4);
    magic = ntohs(magic);
    len = ntohl(len);

    if (magic != PROTO_MAGIC || hdr[2] != PROTO_VERSION)
        return -1;
    if (len > CTF_PROTO_MAX_PAYLOAD)
        return -1;

    proto_msg_t *m = proto_msg_new(hdr[3]);
    if (!m)
        return -1;

    if (len) {
        if (buf_reserve(&m->payload, len) != 0) {
            proto_msg_free(m);
            return -1;
        }
        if (fd_read_full(fd, m->payload.data, len) != 0) {
            proto_msg_free(m);
            return -1;
        }
        m->payload.len = len;
    }

    *out = m;
    return 0;
}

const char *proto_type_name(uint8_t type)
{
    switch (type) {
    case PROTO_HELLO:     return "HELLO";
    case PROTO_HELLO_ACK: return "HELLO_ACK";
    case PROTO_CALC_REQ:  return "CALC_REQ";
    case PROTO_CALC_RES:  return "CALC_RES";
    case PROTO_PING:      return "PING";
    case PROTO_PONG:      return "PONG";
    case PROTO_ERROR:     return "ERROR";
    case PROTO_BYE:       return "BYE";
    case PROTO_ALGO_LIST:     return "ALGO_LIST";
    case PROTO_ALGO_LIST_RES: return "ALGO_LIST_RES";
    default:              return "UNKNOWN";
    }
}
