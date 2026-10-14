#define _GNU_SOURCE
#include "common/util.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Dynamic byte buffer                                                 */
/* ------------------------------------------------------------------ */

void buf_init(buf_t *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void buf_free(buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void buf_reset(buf_t *b)
{
    b->len = 0;
}

int buf_reserve(buf_t *b, size_t extra)
{
    size_t need = b->len + extra;
    if (need <= b->cap)
        return 0;

    size_t cap = b->cap ? b->cap : 64;
    while (cap < need) {
        if (cap > (SIZE_MAX / 2))
            return -1;
        cap *= 2;
    }

    uint8_t *p = realloc(b->data, cap);
    if (!p)
        return -1;
    b->data = p;
    b->cap = cap;
    return 0;
}

int buf_append(buf_t *b, const void *data, size_t len)
{
    if (len == 0)
        return 0;
    if (buf_reserve(b, len) != 0)
        return -1;
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return 0;
}

int buf_append_byte(buf_t *b, uint8_t c)
{
    return buf_append(b, &c, 1);
}

int buf_append_str(buf_t *b, const char *s)
{
    return buf_append(b, s, strlen(s));
}

int buf_appendf(buf_t *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        return -1;
    }
    if (buf_reserve(b, (size_t)n + 1) != 0) {
        va_end(ap2);
        return -1;
    }
    vsnprintf((char *)b->data + b->len, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
    return 0;
}

int buf_append_cstr(buf_t *b, const void *data, size_t len)
{
    if (buf_append(b, data, len) != 0)
        return -1;
    uint8_t nul = 0;
    return buf_append(b, &nul, 1) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Socket helpers                                                      */
/* ------------------------------------------------------------------ */

int fd_read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1; /* peer closed */
        got += (size_t)n;
    }
    return 0;
}

int fd_write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

int set_nonblock(int fd, int on)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (on)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

int make_tcp_listener(const char *bind_addr, int port, int backlog)
{
    struct addrinfo hints, *res = NULL, *rp;
    char portstr[16];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    snprintf(portstr, sizeof portstr, "%d", port);

    int rc = getaddrinfo(bind_addr, portstr, &hints, &res);
    if (rc != 0) {
        log_error("net", "getaddrinfo(%s:%d): %s", bind_addr ? bind_addr : "*",
                  port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        log_error("net", "unable to bind %s:%d: %s",
                  bind_addr ? bind_addr : "*", port, strerror(errno));
        return -1;
    }
    if (listen(fd, backlog) != 0) {
        log_error("net", "listen: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int tcp_connect(const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *rp;
    char portstr[16];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);

    int rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        log_error("net", "getaddrinfo(%s:%d): %s", host, port,
                  gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    return fd;
}

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */

static log_level_t g_log_level = LOG_INFO;

void log_set_level(log_level_t level)
{
    g_log_level = level;
}

void log_msg(log_level_t level, const char *module, const char *fmt, ...)
{
    if (level < g_log_level)
        return;

    static const char *names[] = { "DEBUG", "INFO", "WARN", "ERROR" };

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    char stamp[32];
    strftime(stamp, sizeof stamp, "%H:%M:%S", &tm);

    fprintf(stderr, "%s.%03ld [%-5s] %-6s ", stamp, ts.tv_nsec / 1000000,
            names[level], module ? module : "-");

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
    fflush(stderr);
}

/* ------------------------------------------------------------------ */
/* Time                                                                */
/* ------------------------------------------------------------------ */

uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

void sleep_ms(unsigned ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000u;
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    nanosleep(&ts, NULL);
}

/* ------------------------------------------------------------------ */
/* Misc                                                                */
/* ------------------------------------------------------------------ */

void json_escape(buf_t *out, const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  buf_append_str(out, "\\\""); break;
        case '\\': buf_append_str(out, "\\\\"); break;
        case '\n': buf_append_str(out, "\\n"); break;
        case '\r': buf_append_str(out, "\\r"); break;
        case '\t': buf_append_str(out, "\\t"); break;
        case '\b': buf_append_str(out, "\\b"); break;
        case '\f': buf_append_str(out, "\\f"); break;
        default:
            if (c < 0x20) {
                char esc[8];
                snprintf(esc, sizeof esc, "\\u%04x", c);
                buf_append_str(out, esc);
            } else {
                buf_append_byte(out, c);
            }
        }
    }
}

void hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}
