#define _GNU_SOURCE
#include "web/web.h"

#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common/util.h"
#include "config.h"
#include "proto/proto.h"

#define MOD "web"

/* ================================================================== */
/* Algorithm cache (mirror of the logic server registry)               */
/* ================================================================== */

#define WEB_MAX_ALGOS 64

typedef struct {
    uint16_t id;
    char     name[64];
    char     desc[192];
} algo_info_t;

/* ================================================================== */
/* Job store                                                           */
/* ================================================================== */

enum { JOB_PENDING = 0, JOB_DONE = 1, JOB_ERROR = 2 };

typedef struct job {
    uint64_t     id;
    int          status;
    buf_t        result;
    char         error[192];
    uint64_t     created_ms;
    struct job  *next;
} job_t;

/* ================================================================== */
/* Server                                                              */
/* ================================================================== */

struct web_server {
    int             listen_fd;
    volatile int    running;
    char            templates_dir[512];
    pthread_t       accept_thread;

    /* logic link */
    char            logic_host[128];
    int             logic_port;
    int             logic_fd;
    volatile int    logic_up;
    pthread_mutex_t logic_lock;
    pthread_t       logic_thread;

    /* jobs */
    job_t          *buckets[CTF_JOB_BUCKETS];
    pthread_mutex_t jobs_lock;
    uint64_t        next_id;

    /* algorithm registry cache */
    algo_info_t     algos[WEB_MAX_ALGOS];
    size_t          algo_count;
    pthread_mutex_t algo_lock;
};

/* ================================================================== */
/* Job store helpers                                                   */
/* ================================================================== */

static job_t *job_lookup(web_server_t *s, uint64_t id)
{
    job_t *j = s->buckets[id & (CTF_JOB_BUCKETS - 1)];
    while (j && j->id != id)
        j = j->next;
    return j;
}

static job_t *job_create(web_server_t *s, uint64_t id)
{
    job_t *j = calloc(1, sizeof *j);
    if (!j)
        return NULL;
    j->id = id;
    j->status = JOB_PENDING;
    j->created_ms = now_ms();
    buf_init(&j->result);

    size_t b = id & (CTF_JOB_BUCKETS - 1);
    pthread_mutex_lock(&s->jobs_lock);
    j->next = s->buckets[b];
    s->buckets[b] = j;
    pthread_mutex_unlock(&s->jobs_lock);
    return j;
}

static void job_set_result(web_server_t *s, uint64_t id, int status,
                           const void *data, size_t len, const char *err)
{
    pthread_mutex_lock(&s->jobs_lock);
    job_t *j = job_lookup(s, id);
    if (j) {
        j->status = status;
        buf_reset(&j->result);
        if (status == JOB_DONE && data && len)
            buf_append(&j->result, data, len);
        if (err)
            snprintf(j->error, sizeof j->error, "%s", err);
        else
            j->error[0] = '\0';
    }
    pthread_mutex_unlock(&s->jobs_lock);
}

static int job_snapshot(web_server_t *s, uint64_t id, int *status,
                        buf_t *result, char *err, size_t errsz)
{
    int found = 0;
    pthread_mutex_lock(&s->jobs_lock);
    job_t *j = job_lookup(s, id);
    if (j) {
        found = 1;
        *status = j->status;
        buf_reset(result);
        if (j->result.len)
            buf_append(result, j->result.data, j->result.len);
        if (err)
            snprintf(err, errsz, "%s", j->error);
    }
    pthread_mutex_unlock(&s->jobs_lock);
    return found;
}

static void job_gc(web_server_t *s)
{
    uint64_t cutoff = now_ms();
    pthread_mutex_lock(&s->jobs_lock);
    for (size_t b = 0; b < CTF_JOB_BUCKETS; b++) {
        job_t **pp = &s->buckets[b];
        while (*pp) {
            job_t *j = *pp;
            if (j->status != JOB_PENDING &&
                cutoff - j->created_ms > CTF_JOB_TTL_MS) {
                *pp = j->next;
                buf_free(&j->result);
                free(j);
            } else {
                pp = &j->next;
            }
        }
    }
    pthread_mutex_unlock(&s->jobs_lock);
}

/* ================================================================== */
/* Logic client                                                        */
/* ================================================================== */

static int logic_send(web_server_t *s, const proto_msg_t *m)
{
    int rc = -1;
    pthread_mutex_lock(&s->logic_lock);
    if (s->logic_fd >= 0 && s->logic_up) {
        rc = proto_send(s->logic_fd, m);
        if (rc != 0) {
            shutdown(s->logic_fd, SHUT_RDWR);
            s->logic_up = 0;
        }
    }
    pthread_mutex_unlock(&s->logic_lock);
    return rc;
}

static void handle_algo_list(web_server_t *s, const proto_msg_t *m)
{
    algo_info_t tmp[WEB_MAX_ALGOS];
    size_t n = 0;

    proto_iter_t it;
    proto_iter_init(&it, m);
    uint32_t tag, len;
    const void *val;

    int have_id = 0;
    uint16_t id = 0;
    char name[64] = { 0 };
    char desc[192] = { 0 };

    while (proto_iter_next(&it, &tag, &val, &len) && n < WEB_MAX_ALGOS) {
        switch (tag) {
        case PROTO_TAG_ALGO:
            if (len == 4) {
                uint32_t be;
                memcpy(&be, val, 4);
                id = (uint16_t)ntohl(be);
                have_id = 1;
            }
            break;
        case PROTO_TAG_ALGO_NAME:
            snprintf(name, sizeof name, "%.*s", (int)len, (const char *)val);
            break;
        case PROTO_TAG_ALGO_DESC:
            snprintf(desc, sizeof desc, "%.*s", (int)len, (const char *)val);
            if (have_id) {
                tmp[n].id = id;
                snprintf(tmp[n].name, sizeof tmp[n].name, "%s", name);
                snprintf(tmp[n].desc, sizeof tmp[n].desc, "%s", desc);
                n++;
                have_id = 0;
            }
            break;
        default:
            break;
        }
    }

    pthread_mutex_lock(&s->algo_lock);
    memcpy(s->algos, tmp, n * sizeof tmp[0]);
    s->algo_count = n;
    pthread_mutex_unlock(&s->algo_lock);
    log_info(MOD, "received %zu algorithm(s) from logic server", n);
}

static void handle_calc_res(web_server_t *s, const proto_msg_t *m)
{
    uint64_t id = 0;
    uint32_t status = PROTO_STATUS_ERROR;
    proto_get_u64(m, PROTO_TAG_REQ_ID, &id);
    proto_get_u32(m, PROTO_TAG_STATUS, &status);

    uint32_t len = 0;
    const void *result = proto_get(m, PROTO_TAG_RESULT, &len);
    const char *err = proto_get_str(m, PROTO_TAG_ERROR);

    if (status == PROTO_STATUS_OK)
        job_set_result(s, id, JOB_DONE, result, len, NULL);
    else
        job_set_result(s, id, JOB_ERROR, NULL, 0,
                       err ? err : "logic server reported an error");
}

static void handle_logic_msg(web_server_t *s, const proto_msg_t *m)
{
    switch (m->type) {
    case PROTO_HELLO_ACK:
        log_info(MOD, "logic handshake complete");
        break;
    case PROTO_ALGO_LIST_RES:
        handle_algo_list(s, m);
        break;
    case PROTO_CALC_RES:
        handle_calc_res(s, m);
        break;
    case PROTO_PONG:
        break;
    case PROTO_ERROR:
        log_warn(MOD, "logic error: %s",
                 proto_get_str(m, PROTO_TAG_ERROR) ?: "(none)");
        break;
    default:
        log_debug(MOD, "ignoring %s from logic", proto_type_name(m->type));
        break;
    }
}

static void *logic_main(void *arg)
{
    web_server_t *s = arg;
    while (s->running) {
        int fd = tcp_connect(s->logic_host, s->logic_port);
        if (fd < 0) {
            log_warn(MOD, "cannot reach logic server at %s:%d, retrying",
                     s->logic_host, s->logic_port);
            sleep_ms(CTF_LOGIC_RECONNECT_MS);
            continue;
        }

        pthread_mutex_lock(&s->logic_lock);
        s->logic_fd = fd;
        s->logic_up = 1;
        pthread_mutex_unlock(&s->logic_lock);
        log_info(MOD, "connected to logic server %s:%d", s->logic_host,
                 s->logic_port);

        proto_msg_t *hello = proto_msg_new(PROTO_HELLO);
        proto_add_u32(hello, PROTO_TAG_VERSION, PROTO_VERSION);
        logic_send(s, hello);
        proto_msg_free(hello);

        proto_msg_t *list = proto_msg_new(PROTO_ALGO_LIST);
        logic_send(s, list);
        proto_msg_free(list);

        proto_msg_t *msg = NULL;
        while (s->running && proto_recv(fd, &msg) == 0) {
            handle_logic_msg(s, msg);
            proto_msg_free(msg);
            msg = NULL;
        }

        pthread_mutex_lock(&s->logic_lock);
        int old = s->logic_fd;
        s->logic_fd = -1;
        s->logic_up = 0;
        pthread_mutex_unlock(&s->logic_lock);
        if (old >= 0)
            close(old);
        log_warn(MOD, "lost logic server connection");

        if (s->running) {
            sleep_ms(CTF_LOGIC_RECONNECT_MS);
        }
    }
    return NULL;
}

/* ================================================================== */
/* HTTP helpers                                                        */
/* ================================================================== */

static int http_respond(int fd, int code, const char *ctype, const void *body,
                        size_t len)
{
    const char *reason = "OK";
    switch (code) {
    case 200: reason = "OK"; break;
    case 400: reason = "Bad Request"; break;
    case 404: reason = "Not Found"; break;
    case 405: reason = "Method Not Allowed"; break;
    case 500: reason = "Internal Server Error"; break;
    case 503: reason = "Service Unavailable"; break;
    default: break;
    }

    buf_t h;
    buf_init(&h);
    buf_appendf(&h, "HTTP/1.1 %d %s\r\n", code, reason);
    buf_appendf(&h, "Content-Type: %s\r\n", ctype);
    buf_appendf(&h, "Content-Length: %zu\r\n", len);
    buf_append_str(&h, "Connection: close\r\n");
    buf_append_str(&h, "Cache-Control: no-store\r\n");
    buf_append_str(&h, "\r\n");

    int rc = fd_write_full(fd, h.data, h.len);
    if (rc == 0 && len)
        rc = fd_write_full(fd, body, len);
    buf_free(&h);
    return rc;
}

static int http_respond_json(int fd, int code, buf_t *json)
{
    int rc = http_respond(fd, code, "application/json", json->data, json->len);
    return rc;
}

/* Locate "\r\n\r\n" in `d`; returns index just past it or -1. */
static ssize_t find_header_end(const uint8_t *d, size_t n)
{
    for (size_t i = 0; i + 3 < n; i++)
        if (d[i] == '\r' && d[i + 1] == '\n' && d[i + 2] == '\r' &&
            d[i + 3] == '\n')
            return (ssize_t)(i + 4);
    return -1;
}

static int ci_prefix(const char *s, size_t n, const char *name)
{
    size_t i = 0;
    for (; name[i]; i++) {
        if (i >= n || tolower((unsigned char)s[i]) != tolower((unsigned char)name[i]))
            return 0;
    }
    return 1;
}

/* Extract a header value into `out`. */
static int header_value(const uint8_t *hdr, size_t n, const char *name,
                        char *out, size_t outsz)
{
    size_t i = 0;
    while (i < n) {
        size_t eol = i;
        while (eol < n && hdr[eol] != '\n')
            eol++;
        size_t len = eol > i ? eol - i : 0;
        if (len && hdr[i + len - 1] == '\r')
            len--;

        const char *line = (const char *)(hdr + i);
        if (ci_prefix(line, len, name)) {
            size_t k = strlen(name);
            if (k <= len && line[k] == ':') {
                k++;
                while (k < len && (line[k] == ' ' || line[k] == '\t'))
                    k++;
                size_t v = 0;
                while (k < len && line[k] != '\r' && v + 1 < outsz)
                    out[v++] = line[k++];
                out[v] = '\0';
                return 0;
            }
        }
        i = eol + 1;
    }
    return -1;
}

typedef struct {
    char     method[8];
    char     path[2048];
    uint8_t *body;
    size_t   body_len;
} http_req_t;

static int read_http_request(int fd, buf_t *raw, http_req_t *req)
{
    buf_init(raw);
    ssize_t hdr_end = -1;

    while (1) {
        hdr_end = find_header_end(raw->data, raw->len);
        if (hdr_end >= 0)
            break;
        uint8_t tmp[8192];
        ssize_t n = read(fd, tmp, sizeof tmp);
        if (n <= 0)
            return -1;
        if (raw->len + (size_t)n > CTF_MAX_HTTP_REQUEST)
            return -1;
        buf_append(raw, tmp, (size_t)n);
    }

    /* request line */
    size_t eol = 0;
    while (eol < raw->len && raw->data[eol] != '\r' && raw->data[eol] != '\n')
        eol++;
    const char *line = (const char *)raw->data;
    size_t p = 0, m = 0;
    while (p < eol && !isspace((unsigned char)line[p]) && m + 1 < sizeof req->method)
        req->method[m++] = line[p++];
    req->method[m] = '\0';
    while (p < eol && isspace((unsigned char)line[p]))
        p++;
    size_t pathlen = 0;
    while (p < eol && !isspace((unsigned char)line[p]) && pathlen + 1 < sizeof req->path)
        req->path[pathlen++] = line[p++];
    req->path[pathlen] = '\0';

    size_t content_len = 0;
    char clen[32];
    if (header_value(raw->data, (size_t)hdr_end, "content-length", clen,
                     sizeof clen) == 0)
        content_len = (size_t)strtoul(clen, NULL, 10);

    if (content_len > CTF_MAX_HTTP_REQUEST)
        return -1;

    while (raw->len < (size_t)hdr_end + content_len) {
        uint8_t tmp[8192];
        ssize_t n = read(fd, tmp, sizeof tmp);
        if (n <= 0)
            return -1;
        buf_append(raw, tmp, (size_t)n);
    }

    req->body = raw->data + hdr_end;
    req->body_len = content_len;
    /* NUL terminate the body for the JSON parser. */
    uint8_t nul = 0;
    buf_append(raw, &nul, 1);
    return 0;
}

/* ================================================================== */
/* Tiny JSON reader (flat objects only - exactly what the SPA sends)   */
/* ================================================================== */

static const char *json_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    return p;
}

/* Find "key" and leave *pp pointing at the value. */
static const char *json_find(const char *json, const char *key)
{
    size_t klen = strlen(key);
    for (const char *p = json; (p = strchr(p, '"')) != NULL; p++) {
        p++;
        if (strncmp(p, key, klen) == 0 && p[klen] == '"') {
            const char *c = json_skip_ws(p + klen + 1);
            if (*c == ':')
                return json_skip_ws(c + 1);
        }
    }
    return NULL;
}

static void utf8_append(buf_t *out, unsigned cp)
{
    if (cp < 0x80) {
        buf_append_byte(out, (uint8_t)cp);
    } else if (cp < 0x800) {
        buf_append_byte(out, (uint8_t)(0xc0 | (cp >> 6)));
        buf_append_byte(out, (uint8_t)(0x80 | (cp & 0x3f)));
    } else {
        buf_append_byte(out, (uint8_t)(0xe0 | (cp >> 12)));
        buf_append_byte(out, (uint8_t)(0x80 | ((cp >> 6) & 0x3f)));
        buf_append_byte(out, (uint8_t)(0x80 | (cp & 0x3f)));
    }
}

static int json_parse_string(const char **pp, buf_t *out)
{
    const char *p = *pp;
    if (*p != '"')
        return -1;
    p++;
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            switch (*p) {
            case 'n': buf_append_byte(out, '\n'); p++; break;
            case 'r': buf_append_byte(out, '\r'); p++; break;
            case 't': buf_append_byte(out, '\t'); p++; break;
            case 'b': buf_append_byte(out, '\b'); p++; break;
            case 'f': buf_append_byte(out, '\f'); p++; break;
            case '"': buf_append_byte(out, '"'); p++; break;
            case '\\': buf_append_byte(out, '\\'); p++; break;
            case '/': buf_append_byte(out, '/'); p++; break;
            case 'u': {
                unsigned cp = 0;
                for (int i = 0; i < 4 && isxdigit((unsigned char)p[1]); i++) {
                    char c = *++p;
                    cp = cp * 16 + (unsigned)(isdigit((unsigned char)c)
                                                  ? c - '0'
                                                  : (tolower(c) - 'a' + 10));
                }
                p++;
                utf8_append(out, cp);
                break;
            }
            default:
                if (*p) { buf_append_byte(out, (uint8_t)*p); p++; }
                break;
            }
        } else {
            buf_append_byte(out, (uint8_t)*p);
            p++;
        }
    }
    if (*p != '"')
        return -1;
    *pp = p + 1;
    return 0;
}

/* ================================================================== */
/* Static files                                                        */
/* ================================================================== */

static const char *content_type_for(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot)
        return "application/octet-stream";
    if (!strcmp(dot, ".html")) return "text/html; charset=utf-8";
    if (!strcmp(dot, ".js"))   return "application/javascript; charset=utf-8";
    if (!strcmp(dot, ".css"))  return "text/css; charset=utf-8";
    if (!strcmp(dot, ".json")) return "application/json";
    if (!strcmp(dot, ".svg"))  return "image/svg+xml";
    if (!strcmp(dot, ".ico"))  return "image/x-icon";
    return "text/plain; charset=utf-8";
}

static int read_file(const char *path, buf_t *out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0 ||
        (size_t)st.st_size > CTF_MAX_FILE_BYTES) {
        close(fd);
        return -1;
    }
    if (buf_reserve(out, (size_t)st.st_size + 1) != 0) {
        close(fd);
        return -1;
    }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t n = read(fd, out->data + out->len + got,
                         (size_t)st.st_size - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        got += (size_t)n;
    }
    out->len += got;
    close(fd);
    return 0;
}

/* Does `dir` look like a usable templates directory (has index.html)? */
static int dir_has_index(const char *dir)
{
    char p[1024];
    int n = snprintf(p, sizeof p, "%s/index.html", dir);
    if (n <= 0 || (size_t)n >= sizeof p)
        return 0;
    return access(p, R_OK) == 0;
}

/*
 * Templates are configured with a relative default ("src/templates"), which
 * only resolves correctly when the process is launched from the repository
 * root.  To make the server runnable from anywhere we probe a handful of
 * candidate locations: the user supplied path, the current directory, and
 * paths relative to the executable itself.
 */
static void resolve_templates_dir(const char *given, char *out, size_t outsz)
{
    char exedir[1024] = "";
    char exebuf[1024];
    ssize_t l = readlink("/proc/self/exe", exebuf, sizeof exebuf - 1);
    if (l > 0) {
        exebuf[l] = '\0';
        char *slash = strrchr(exebuf, '/');
        if (slash) {
            *slash = '\0';
            snprintf(exedir, sizeof exedir, "%s", exebuf);
        }
    }

    char c1[1024] = "", c2[1024] = "", c3[1024] = "", c4[1024] = "";
    const char *cands[8];
    int n = 0;
    if (given && *given)
        cands[n++] = given;
    cands[n++] = CTF_TEMPLATES_DIR;
    cands[n++] = "templates";
    cands[n++] = "src/templates";
    if (exedir[0]) {
        snprintf(c1, sizeof c1, "%s/../%s", exedir, CTF_TEMPLATES_DIR);
        snprintf(c2, sizeof c2, "%s/../templates", exedir);
        snprintf(c3, sizeof c3, "%s/templates", exedir);
        snprintf(c4, sizeof c4, "%s/%s", exedir, CTF_TEMPLATES_DIR);
        cands[n++] = c1;
        cands[n++] = c2;
        cands[n++] = c3;
        cands[n++] = c4;
    }

    for (int i = 0; i < n; i++) {
        if (dir_has_index(cands[i])) {
            snprintf(out, outsz, "%s", cands[i]);
            return;
        }
    }
    /* Nothing matched; keep the caller's choice so the 404s are explainable. */
    snprintf(out, outsz, "%s", (given && *given) ? given : CTF_TEMPLATES_DIR);
}

static void serve_static(web_server_t *s, int fd, const char *path)
{
    if (strstr(path, "..")) {
        http_respond(fd, 400, "text/plain", "bad path\n", 9);
        return;
    }
    const char *rel = (strcmp(path, "/") == 0) ? "index.html" : path + 1;

    char full[1024];
    int n = snprintf(full, sizeof full, "%s/%s", s->templates_dir, rel);
    if (n <= 0 || (size_t)n >= sizeof full) {
        http_respond(fd, 400, "text/plain", "bad path\n", 9);
        return;
    }

    buf_t file;
    buf_init(&file);
    if (read_file(full, &file) != 0) {
        buf_reset(&file);
        buf_append_str(&file, "404 not found: ");
        buf_append_str(&file, rel);
        buf_append_byte(&file, '\n');
        http_respond(fd, 404, "text/plain", file.data, file.len);
        buf_free(&file);
        return;
    }
    http_respond(fd, 200, content_type_for(rel), file.data, file.len);
    buf_free(&file);
}

/* ================================================================== */
/* API handlers                                                        */
/* ================================================================== */

static void api_algos(web_server_t *s, int fd)
{
    buf_t out;
    buf_init(&out);
    buf_append_str(&out, "{\"algos\":[");
    pthread_mutex_lock(&s->algo_lock);
    for (size_t i = 0; i < s->algo_count; i++) {
        if (i)
            buf_append_byte(&out, ',');
        buf_appendf(&out, "{\"id\":%u,\"name\":\"", s->algos[i].id);
        json_escape(&out, s->algos[i].name, strlen(s->algos[i].name));
        buf_append_str(&out, "\",\"description\":\"");
        json_escape(&out, s->algos[i].desc, strlen(s->algos[i].desc));
        buf_append_str(&out, "\"}");
    }
    pthread_mutex_unlock(&s->algo_lock);
    buf_append_str(&out, "]}");
    http_respond_json(fd, 200, &out);
    buf_free(&out);
}

static void api_jobs(web_server_t *s, int fd)
{
    job_gc(s);
    buf_t out;
    buf_init(&out);
    buf_append_str(&out, "{\"jobs\":[");
    int first = 1;
    pthread_mutex_lock(&s->jobs_lock);
    for (size_t b = 0; b < CTF_JOB_BUCKETS; b++) {
        for (job_t *j = s->buckets[b]; j; j = j->next) {
            if (!first)
                buf_append_byte(&out, ',');
            first = 0;
            const char *st = j->status == JOB_PENDING ? "pending"
                             : j->status == JOB_DONE  ? "done"
                                                      : "error";
            buf_appendf(&out, "{\"id\":%llu,\"status\":\"%s\"}",
                        (unsigned long long)j->id, st);
        }
    }
    pthread_mutex_unlock(&s->jobs_lock);
    buf_append_str(&out, "]}");
    http_respond_json(fd, 200, &out);
    buf_free(&out);
}

static void api_health(web_server_t *s, int fd)
{
    buf_t out;
    buf_init(&out);
    pthread_mutex_lock(&s->algo_lock);
    size_t na = s->algo_count;
    pthread_mutex_unlock(&s->algo_lock);
    buf_appendf(&out, "{\"logic\":\"%s\",\"algorithms\":%zu}",
                s->logic_up ? "up" : "down", na);
    http_respond_json(fd, s->logic_up ? 200 : 503, &out);
    buf_free(&out);
}

static int find_algo_by_name(web_server_t *s, const char *name, uint16_t *id)
{
    int found = 0;
    pthread_mutex_lock(&s->algo_lock);
    for (size_t i = 0; i < s->algo_count; i++) {
        if (strcmp(s->algos[i].name, name) == 0) {
            *id = s->algos[i].id;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&s->algo_lock);
    return found;
}

static void api_calc(web_server_t *s, int fd, const char *body, size_t body_len)
{
    (void)body_len; /* body is NUL terminated by the request reader */
    buf_t err;
    buf_init(&err);

    char algo_name[64];
    buf_t input;
    buf_init(&input);
    char hash_name[32] = { 0 };
    buf_t alphabet;
    buf_init(&alphabet);
    long keylen = 1, flags = 0, word_len = 0;
    int have_algo = 0, have_input = 0;

    const char *v = json_find(body, "algo");
    if (v && *v == '"') {
        buf_t tmp;
        buf_init(&tmp);
        if (json_parse_string(&v, &tmp) == 0) {
            snprintf(algo_name, sizeof algo_name, "%.*s", (int)tmp.len,
                     (const char *)tmp.data);
            have_algo = 1;
        }
        buf_free(&tmp);
    }
    v = json_find(body, "input");
    if (v && *v == '"') {
        if (json_parse_string(&v, &input) == 0)
            have_input = 1;
    }
    v = json_find(body, "keylen");
    if (v && isdigit((unsigned char)*v))
        keylen = strtol(v, NULL, 10);
    v = json_find(body, "flags");
    if (v && isdigit((unsigned char)*v))
        flags = strtol(v, NULL, 10);

    /* Hash brute force extras.  The alphabet is forwarded verbatim so the
     * logic server always receives exactly what the caller typed. */
    v = json_find(body, "hash");
    if (v && *v == '"') {
        buf_t tmp;
        buf_init(&tmp);
        if (json_parse_string(&v, &tmp) == 0)
            snprintf(hash_name, sizeof hash_name, "%.*s", (int)tmp.len,
                     (const char *)tmp.data);
        buf_free(&tmp);
    }
    v = json_find(body, "alphabet");
    if (v && *v == '"')
        json_parse_string(&v, &alphabet);
    v = json_find(body, "length");
    if (!v)
        v = json_find(body, "word_len");
    if (v && isdigit((unsigned char)*v))
        word_len = strtol(v, NULL, 10);

    if (!have_algo || !have_input) {
        buf_append_str(&err, "{\"error\":\"missing 'algo' or 'input'\"}");
        http_respond_json(fd, 400, &err);
        goto out;
    }
    if (input.len > CTF_MAX_INPUT_BYTES) {
        buf_append_str(&err, "{\"error\":\"input too large\"}");
        http_respond_json(fd, 400, &err);
        goto out;
    }

    uint16_t algo_id = 0;
    if (!find_algo_by_name(s, algo_name, &algo_id)) {
        buf_appendf(&err, "{\"error\":\"unknown algorithm '%s'\"}",
                    algo_name);
        http_respond_json(fd, 400, &err);
        goto out;
    }

    uint64_t id;
    pthread_mutex_lock(&s->jobs_lock);
    id = ++s->next_id;
    pthread_mutex_unlock(&s->jobs_lock);

    job_t *job = job_create(s, id);
    if (!job) {
        buf_append_str(&err, "{\"error\":\"out of memory\"}");
        http_respond_json(fd, 500, &err);
        goto out;
    }

    proto_msg_t *req = proto_msg_new(PROTO_CALC_REQ);
    if (!req) {
        job_set_result(s, id, JOB_ERROR, NULL, 0, "out of memory");
        buf_append_str(&err, "{\"error\":\"out of memory\"}");
        http_respond_json(fd, 500, &err);
        goto out;
    }
    proto_add_u64(req, PROTO_TAG_REQ_ID, id);
    proto_add_u32(req, PROTO_TAG_ALGO, algo_id);
    proto_add(req, PROTO_TAG_INPUT, input.data, (uint32_t)input.len);
    proto_add_u32(req, PROTO_TAG_KEY_LEN, (uint32_t)keylen);
    proto_add_u32(req, PROTO_TAG_FLAGS, (uint32_t)flags);
    if (hash_name[0])
        proto_add_str(req, PROTO_TAG_HASH, hash_name);
    if (alphabet.len)
        proto_add(req, PROTO_TAG_ALPHABET, alphabet.data,
                  (uint32_t)alphabet.len);
    if (word_len > 0)
        proto_add_u32(req, PROTO_TAG_LENGTH, (uint32_t)word_len);

    if (logic_send(s, req) != 0) {
        proto_msg_free(req);
        job_set_result(s, id, JOB_ERROR, NULL, 0, "logic server unavailable");
        buf_appendf(&err,
                    "{\"id\":%llu,\"error\":\"logic server unavailable\"}",
                    (unsigned long long)id);
        http_respond_json(fd, 503, &err);
        goto out;
    }
    proto_msg_free(req);
    log_info(MOD, "queued job %llu (%s, %zu bytes, keylen %ld)",
             (unsigned long long)id, algo_name, input.len, keylen);

    buf_appendf(&err, "{\"id\":%llu,\"status\":\"pending\"}",
                (unsigned long long)id);
    http_respond_json(fd, 202, &err);

out:
    buf_free(&input);
    buf_free(&alphabet);
    buf_free(&err);
}

static void api_result(web_server_t *s, int fd, const char *path)
{
    job_gc(s);
    const char *q = strchr(path, '?');
    uint64_t id = 0;
    int have_id = 0;
    if (q) {
        const char *p = strstr(q, "id=");
        if (p)
            id = strtoull(p + 3, NULL, 10), have_id = 1;
    }

    buf_t out;
    buf_init(&out);

    if (!have_id) {
        buf_append_str(&out, "{\"error\":\"missing id\"}");
        http_respond_json(fd, 400, &out);
        buf_free(&out);
        return;
    }

    int status;
    buf_t result;
    buf_init(&result);
    char err[192] = { 0 };

    if (!job_snapshot(s, id, &status, &result, err, sizeof err)) {
        buf_append_str(&out, "{\"error\":\"unknown job\"}");
        http_respond_json(fd, 404, &out);
        goto done;
    }

    const char *st = status == JOB_PENDING ? "pending"
                     : status == JOB_DONE  ? "done"
                                           : "error";
    buf_appendf(&out, "{\"id\":%llu,\"status\":\"%s\",\"result\":\"",
                (unsigned long long)id, st);
    json_escape(&out, (const char *)result.data, result.len);
    buf_append_str(&out, "\",\"error\":\"");
    json_escape(&out, err, strlen(err));
    buf_append_str(&out, "\"}");
    http_respond_json(fd, 200, &out);

done:
    buf_free(&result);
    buf_free(&out);
}

/* ================================================================== */
/* Request dispatch                                                    */
/* ================================================================== */

static void handle_request(web_server_t *s, int fd, http_req_t *req)
{
    if (strcmp(req->method, "GET") == 0) {
        if (strncmp(req->path, "/api/", 5) == 0) {
            if (strncmp(req->path, "/api/algos", 10) == 0)
                api_algos(s, fd);
            else if (strncmp(req->path, "/api/jobs", 9) == 0)
                api_jobs(s, fd);
            else if (strncmp(req->path, "/api/result", 11) == 0)
                api_result(s, fd, req->path);
            else if (strncmp(req->path, "/api/health", 11) == 0)
                api_health(s, fd);
            else
                http_respond(fd, 404, "text/plain", "no such endpoint\n", 17);
        } else {
            serve_static(s, fd, req->path);
        }
    } else if (strcmp(req->method, "POST") == 0) {
        if (strncmp(req->path, "/api/calc", 9) == 0) {
            if (!req->body) {
                http_respond(fd, 400, "text/plain", "empty body\n", 11);
                return;
            }
            api_calc(s, fd, (const char *)req->body, req->body_len);
        } else {
            http_respond(fd, 404, "text/plain", "no such endpoint\n", 17);
        }
    } else {
        http_respond(fd, 405, "text/plain", "method not allowed\n", 19);
    }
}

typedef struct {
    web_server_t *srv;
    int           fd;
} client_t;

static void *client_main(void *arg)
{
    client_t *c = arg;
    buf_t raw;
    http_req_t req;
    memset(&req, 0, sizeof req);

    if (read_http_request(c->fd, &raw, &req) == 0)
        handle_request(c->srv, c->fd, &req);

    buf_free(&raw);
    close(c->fd);
    free(c);
    return NULL;
}

static void *accept_main(void *arg)
{
    web_server_t *s = arg;
    while (s->running) {
        int fd = accept(s->listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            if (!s->running)
                break;
            log_warn(MOD, "accept: %s", strerror(errno));
            continue;
        }
        client_t *c = calloc(1, sizeof *c);
        if (!c) {
            close(fd);
            continue;
        }
        c->srv = s;
        c->fd = fd;
        pthread_t t;
        if (pthread_create(&t, NULL, client_main, c) != 0) {
            close(fd);
            free(c);
            continue;
        }
        pthread_detach(t);
    }
    return NULL;
}

/* ================================================================== */
/* Lifecycle                                                           */
/* ================================================================== */

int web_server_start(web_server_t **out, const char *bind_addr, int port,
                     const char *logic_host, int logic_port,
                     const char *templates_dir)
{
    web_server_t *s = calloc(1, sizeof *s);
    if (!s)
        return -1;

    s->running = 1;
    s->logic_fd = -1;
    s->next_id = 0;
    s->logic_port = logic_port;
    snprintf(s->logic_host, sizeof s->logic_host, "%s", logic_host);
    resolve_templates_dir(templates_dir, s->templates_dir,
                          sizeof s->templates_dir);

    pthread_mutex_init(&s->logic_lock, NULL);
    pthread_mutex_init(&s->jobs_lock, NULL);
    pthread_mutex_init(&s->algo_lock, NULL);

    s->listen_fd = make_tcp_listener(bind_addr, port, CTF_LISTEN_BACKLOG);
    if (s->listen_fd < 0)
        goto fail;

    if (pthread_create(&s->logic_thread, NULL, logic_main, s) != 0)
        goto fail;
    if (pthread_create(&s->accept_thread, NULL, accept_main, s) != 0)
        goto fail;

    log_info(MOD, "serving templates from '%s' on %s:%d", s->templates_dir,
             bind_addr ? bind_addr : "*", port);
    *out = s;
    return 0;

fail:
    s->running = 0;
    if (s->listen_fd >= 0)
        close(s->listen_fd);
    free(s);
    return -1;
}

void web_server_stop(web_server_t *s)
{
    if (!s)
        return;
    s->running = 0;
    if (s->listen_fd >= 0)
        shutdown(s->listen_fd, SHUT_RDWR);

    pthread_mutex_lock(&s->logic_lock);
    if (s->logic_fd >= 0) {
        shutdown(s->logic_fd, SHUT_RDWR);
        close(s->logic_fd);
        s->logic_fd = -1;
    }
    pthread_mutex_unlock(&s->logic_lock);

    pthread_join(s->accept_thread, NULL);
    pthread_join(s->logic_thread, NULL);

    for (size_t b = 0; b < CTF_JOB_BUCKETS; b++) {
        job_t *j = s->buckets[b];
        while (j) {
            job_t *n = j->next;
            buf_free(&j->result);
            free(j);
            j = n;
        }
    }
    if (s->listen_fd >= 0)
        close(s->listen_fd);
    free(s);
}
