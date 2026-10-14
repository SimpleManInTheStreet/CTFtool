#ifndef CTF_UTIL_H
#define CTF_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Dynamic byte buffer                                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_reset(buf_t *b);
int  buf_reserve(buf_t *b, size_t extra);
int  buf_append(buf_t *b, const void *data, size_t len);
int  buf_append_byte(buf_t *b, uint8_t c);
int  buf_append_str(buf_t *b, const char *s);
int  buf_appendf(buf_t *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
/* Append `len` bytes, terminating with an extra NUL for convenience. */
int  buf_append_cstr(buf_t *b, const void *data, size_t len);

/* ------------------------------------------------------------------ */
/* Socket helpers                                                      */
/* ------------------------------------------------------------------ */

int fd_read_full(int fd, void *buf, size_t len);
int fd_write_full(int fd, const void *buf, size_t len);

int make_tcp_listener(const char *bind_addr, int port, int backlog);
int tcp_connect(const char *host, int port);
int set_nonblock(int fd, int on);

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_t;

void log_set_level(log_level_t level);
void log_msg(log_level_t level, const char *module, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#define log_debug(mod, ...) log_msg(LOG_DEBUG, mod, __VA_ARGS__)
#define log_info(mod, ...)  log_msg(LOG_INFO,  mod, __VA_ARGS__)
#define log_warn(mod, ...)  log_msg(LOG_WARN,  mod, __VA_ARGS__)
#define log_error(mod, ...) log_msg(LOG_ERROR, mod, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* Time                                                                */
/* ------------------------------------------------------------------ */

uint64_t now_ms(void);
void     sleep_ms(unsigned ms);

/* ------------------------------------------------------------------ */
/* Misc                                                                */
/* ------------------------------------------------------------------ */

/* Escape `len` bytes from `s` into `out` as a JSON string body
 * (without the surrounding quotes). */
void json_escape(buf_t *out, const char *s, size_t len);

/* Convert a byte count to a short hex representation ("deadbeef"). */
void hex_encode(const uint8_t *in, size_t len, char *out);

#endif /* CTF_UTIL_H */
