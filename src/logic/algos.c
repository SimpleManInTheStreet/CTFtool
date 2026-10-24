#define _GNU_SOURCE
#include "logic/algos.h"

#include <pthread.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

static int is_printable(const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (s[i] < 0x20 || s[i] > 0x7e)
            return 0;
    return 1;
}

/* Rough English-likeness score; higher is more likely to be plaintext. */
static int contains_ci(const uint8_t *s, size_t n, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0 || n < nl)
        return 0;
    for (size_t i = 0; i + nl <= n; i++) {
        size_t j = 0;
        for (; j < nl; j++)
            if (tolower(s[i + j]) != needle[j])
                break;
        if (j == nl)
            return 1;
    }
    return 0;
}

static double text_score(const uint8_t *s, size_t n)
{
    static const double freq[26] = {
        8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.8, 4.0,
        2.4, 6.7, 7.5, 1.9, 0.1, 6.0, 6.3, 9.1, 2.8, 1.0, 2.4, 0.15,
        2.0, 0.07
    };
    double score = 0.0;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = s[i];
        if (c == ' ')
            score += 2.5;
        else if (c >= 'a' && c <= 'z')
            score += freq[c - 'a'];
        else if (c >= 'A' && c <= 'Z')
            score += freq[c - 'A'] * 0.5;
        else if (c >= '0' && c <= '9')
            score += 0.5;
        else if (c == '{' || c == '}' || c == '_' || c == '-')
            score += 0.2; /* flag/leetspeak punctuation is not penalised */
        else
            score -= 1.0;
    }
    /* Strongly favour strings that look like CTF flags. */
    if (contains_ci(s, n, "flag"))
        score += 25.0;
    if (contains_ci(s, n, "ctf"))
        score += 10.0;
    return score;
}

/* ================================================================== */
/* Candidate collection (used by brute forcers)                        */
/* ================================================================== */

#define CAND_MAX_KEY 64

typedef struct {
    uint8_t key[CAND_MAX_KEY];
    uint32_t key_len;
    uint8_t *text; /* malloc'd, exactly text_len bytes */
    size_t   text_len;
    double   score;
} cand_t;

typedef struct {
    cand_t *items;
    size_t len;
    size_t cap;
} cand_vec_t;

static void vec_init(cand_vec_t *v)
{
    v->items = NULL;
    v->len = 0;
    v->cap = 0;
}

static void vec_free(cand_vec_t *v)
{
    for (size_t i = 0; i < v->len; i++)
        free(v->items[i].text);
    free(v->items);
    v->items = NULL;
    v->len = v->cap = 0;
}

static void vec_push(cand_vec_t *v, const uint8_t *key, uint32_t key_len,
                     const uint8_t *text, size_t text_len, double score)
{
    if (v->len == v->cap) {
        size_t cap = v->cap ? v->cap * 2 : 64;
        cand_t *p = realloc(v->items, cap * sizeof *p);
        if (!p)
            return;
        v->items = p;
        v->cap = cap;
    }
    cand_t *c = &v->items[v->len];
    memcpy(c->key, key, key_len);
    c->key_len = key_len;
    c->text = malloc(text_len ? text_len : 1);
    if (!c->text)
        return;
    memcpy(c->text, text, text_len);
    c->text_len = text_len;
    c->score = score;
    v->len++;
}

static int cand_cmp(const void *a, const void *b)
{
    const cand_t *x = a, *y = b;
    if (x->score < y->score)
        return 1;
    if (x->score > y->score)
        return -1;
    return 0;
}

/* ================================================================== */
/* XOR brute force                                                     */
/* ================================================================== */

typedef struct {
    const algo_params_t *p;
    uint64_t start;
    uint64_t end;
    cand_vec_t vec;
} xor_task_t;

static void xor_decode(const uint8_t *in, size_t n, const uint8_t *key,
                       uint32_t key_len, uint8_t *out)
{
    for (size_t i = 0; i < n; i++)
        out[i] = in[i] ^ key[i % key_len];
}

static void *xor_worker(void *arg)
{
    xor_task_t *t = arg;
    const algo_params_t *p = t->p;
    uint8_t *buf = malloc(p->input_len);
    uint8_t key[CAND_MAX_KEY];
    if (!buf)
        return NULL;

    for (uint64_t k = t->start; k < t->end; k++) {
        uint64_t v = k;
        for (uint32_t j = 0; j < p->key_len; j++) {
            key[j] = (uint8_t)(v & 0xff);
            v >>= 8;
        }
        xor_decode(p->input, p->input_len, key, p->key_len, buf);
        if (!is_printable(buf, p->input_len))
            continue;
        vec_push(&t->vec, key, p->key_len, buf, p->input_len,
                 text_score(buf, p->input_len));
    }
    free(buf);
    return NULL;
}

#define XOR_MAX_CANDIDATES 2000

static int xor_brute(const algo_params_t *p, buf_t *out)
{
    if (p->input_len == 0) {
        buf_append_str(out, "error: empty input\n");
        return -1;
    }
    uint32_t key_len = p->key_len ? p->key_len : 1;
    if (key_len > CTF_XOR_MAX_KEYLEN) {
        buf_appendf(out,
                    "error: key length %u exceeds limit %d\n",
                    key_len, CTF_XOR_MAX_KEYLEN);
        return -1;
    }

    uint64_t space = 1;
    for (uint32_t i = 0; i < key_len; i++)
        space *= 256;

    unsigned nthreads = CTF_XOR_INNER_THREADS;
    if ((uint64_t)nthreads > space)
        nthreads = (unsigned)space;
    if (nthreads < 1)
        nthreads = 1;

    pthread_t tids[CTF_XOR_INNER_THREADS];
    xor_task_t tasks[CTF_XOR_INNER_THREADS];
    uint64_t chunk = (space + nthreads - 1) / nthreads;

    unsigned started = 0;
    for (unsigned i = 0; i < nthreads; i++) {
        tasks[i].p = p;
        tasks[i].start = (uint64_t)i * chunk;
        tasks[i].end = tasks[i].start + chunk;
        if (tasks[i].end > space)
            tasks[i].end = space;
        if (tasks[i].start >= tasks[i].end)
            continue;
        vec_init(&tasks[i].vec);
        if (pthread_create(&tids[i], NULL, xor_worker, &tasks[i]) != 0) {
            /* Run this chunk synchronously as a fallback. */
            xor_worker(&tasks[i]);
            tids[i] = 0;
        }
        started++;
    }

    cand_vec_t all;
    vec_init(&all);
    for (unsigned i = 0; i < nthreads; i++) {
        if (tasks[i].start >= tasks[i].end)
            continue;
        if (tids[i])
            pthread_join(tids[i], NULL);
        for (size_t j = 0; j < tasks[i].vec.len; j++)
            vec_push(&all, tasks[i].vec.items[j].key,
                     tasks[i].vec.items[j].key_len,
                     tasks[i].vec.items[j].text,
                     tasks[i].vec.items[j].text_len,
                     tasks[i].vec.items[j].score);
        vec_free(&tasks[i].vec);
    }

    qsort(all.items, all.len, sizeof(cand_t), cand_cmp);

    char hex[CAND_MAX_KEY * 2 + 1];
    size_t reported = all.len < XOR_MAX_CANDIDATES ? all.len : XOR_MAX_CANDIDATES;
    buf_appendf(out, "%zu candidate(s), showing top %zu\n", all.len, reported);
    for (size_t i = 0; i < reported; i++) {
        hex_encode(all.items[i].key, all.items[i].key_len, hex);
        buf_appendf(out, "key=%s score=%6.1f  ", hex, all.items[i].score);
        buf_append(out, all.items[i].text, all.items[i].text_len);
        buf_append_byte(out, '\n');
    }
    if (all.len > reported)
        buf_appendf(out, "... %zu more hidden ...\n", all.len - reported);

    vec_free(&all);
    return 0;
}

/* ================================================================== */
/* Caesar / ROT13 / Atbash                                             */
/* ================================================================== */

static uint8_t shift_char(uint8_t c, int shift)
{
    if (c >= 'a' && c <= 'z')
        return (uint8_t)('a' + ((c - 'a' + shift) % 26 + 26) % 26);
    if (c >= 'A' && c <= 'Z')
        return (uint8_t)('A' + ((c - 'A' + shift) % 26 + 26) % 26);
    return c;
}

static int caesar_brute(const algo_params_t *p, buf_t *out)
{
    if (p->input_len == 0) {
        buf_append_str(out, "error: empty input\n");
        return -1;
    }
    cand_vec_t vec;
    vec_init(&vec);
    uint8_t *buf = malloc(p->input_len);
    if (!buf) {
        buf_append_str(out, "error: out of memory\n");
        return -1;
    }

    buf_append_str(out, "Caesar shift brute force\n");
    for (int shift = 1; shift < 26; shift++) {
        for (size_t i = 0; i < p->input_len; i++)
            buf[i] = shift_char(p->input[i], shift);
        if (!is_printable(buf, p->input_len))
            continue;
        uint8_t key = (uint8_t)shift;
        vec_push(&vec, &key, 1, buf, p->input_len,
                 text_score(buf, p->input_len));
    }
    qsort(vec.items, vec.len, sizeof(cand_t), cand_cmp);

    char hex[3];
    for (size_t i = 0; i < vec.len; i++) {
        hex_encode(vec.items[i].key, 1, hex);
        buf_appendf(out, "rot=%-2s score=%6.1f  ", hex, vec.items[i].score);
        buf_append(out, vec.items[i].text, vec.items[i].text_len);
        buf_append_byte(out, '\n');
    }
    if (vec.len == 0)
        buf_append_str(out, "(no fully printable candidate)\n");

    vec_free(&vec);
    free(buf);
    return 0;
}

static int transform_single(const algo_params_t *p, buf_t *out,
                            uint8_t (*fn)(uint8_t))
{
    if (p->input_len == 0) {
        buf_append_str(out, "error: empty input\n");
        return -1;
    }
    for (size_t i = 0; i < p->input_len; i++)
        buf_append_byte(out, fn(p->input[i]));
    buf_append_byte(out, '\n');
    return 0;
}

static uint8_t rot13_fn(uint8_t c)
{
    return shift_char(c, 13);
}

static uint8_t atbash_fn(uint8_t c)
{
    if (c >= 'a' && c <= 'z')
        return (uint8_t)('z' - (c - 'a'));
    if (c >= 'A' && c <= 'Z')
        return (uint8_t)('Z' - (c - 'A'));
    return c;
}

static int rot13_run(const algo_params_t *p, buf_t *out)
{
    return transform_single(p, out, rot13_fn);
}

static int atbash_run(const algo_params_t *p, buf_t *out)
{
    return transform_single(p, out, atbash_fn);
}

/* ================================================================== */
/* Hex                                                                 */
/* ================================================================== */

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int hex_encode_run(const algo_params_t *p, buf_t *out)
{
    for (size_t i = 0; i < p->input_len; i++)
        buf_appendf(out, "%02x", p->input[i]);
    buf_append_byte(out, '\n');
    return 0;
}

static int hex_decode_run(const algo_params_t *p, buf_t *out)
{
    size_t n = 0;
    uint8_t *tmp = malloc(p->input_len ? p->input_len : 1);
    if (!tmp) {
        buf_append_str(out, "error: out of memory\n");
        return -1;
    }
    int hi = -1;
    for (size_t i = 0; i < p->input_len; i++) {
        int c = p->input[i];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ':')
            continue;
        int v = hex_nibble(c);
        if (v < 0) {
            free(tmp);
            buf_append_str(out, "error: invalid hex digit\n");
            return -1;
        }
        if (hi < 0) {
            hi = v;
        } else {
            tmp[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    /* Render as text when printable, else as hex. */
    if (is_printable(tmp, n)) {
        buf_append(out, tmp, n);
        buf_append_byte(out, '\n');
    } else {
        for (size_t i = 0; i < n; i++)
            buf_appendf(out, "%02x", tmp[i]);
        buf_append_byte(out, '\n');
    }
    free(tmp);
    return 0;
}

/* ================================================================== */
/* Base64                                                              */
/* ================================================================== */

static const char b64_alpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode_run(const algo_params_t *p, buf_t *out)
{
    const uint8_t *in = p->input;
    size_t n = p->input_len;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        int rem = (int)(n - i);
        if (rem > 1)
            v |= (uint32_t)in[i + 1] << 8;
        if (rem > 2)
            v |= in[i + 2];
        buf_append_byte(out, b64_alpha[(v >> 18) & 0x3f]);
        buf_append_byte(out, b64_alpha[(v >> 12) & 0x3f]);
        buf_append_byte(out, rem > 1 ? b64_alpha[(v >> 6) & 0x3f] : '=');
        buf_append_byte(out, rem > 2 ? b64_alpha[v & 0x3f] : '=');
    }
    buf_append_byte(out, '\n');
    return 0;
}

static int b64_val(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static int b64_decode_run(const algo_params_t *p, buf_t *out)
{
    uint8_t *tmp = malloc(p->input_len ? p->input_len : 1);
    if (!tmp) {
        buf_append_str(out, "error: out of memory\n");
        return -1;
    }
    size_t n = 0;
    int quad[4], q = 0;
    for (size_t i = 0; i < p->input_len; i++) {
        int c = p->input[i];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t')
            continue;
        int v = b64_val(c);
        if (v < 0) {
            free(tmp);
            buf_append_str(out, "error: invalid base64 character\n");
            return -1;
        }
        quad[q++] = v;
        if (q == 4) {
            uint32_t w = (uint32_t)quad[0] << 18 | (uint32_t)quad[1] << 12 |
                         (uint32_t)quad[2] << 6 | (uint32_t)quad[3];
            tmp[n++] = (uint8_t)(w >> 16);
            tmp[n++] = (uint8_t)(w >> 8);
            tmp[n++] = (uint8_t)w;
            q = 0;
        }
    }
    if (q == 2) {
        tmp[n++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
    } else if (q == 3) {
        tmp[n++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
        tmp[n++] = (uint8_t)((quad[1] << 4) | (quad[2] >> 2));
    } else if (q == 1) {
        free(tmp);
        buf_append_str(out, "error: bad base64 length\n");
        return -1;
    }

    if (is_printable(tmp, n)) {
        buf_append(out, tmp, n);
        buf_append_byte(out, '\n');
    } else {
        for (size_t i = 0; i < n; i++)
            buf_appendf(out, "%02x", tmp[i]);
        buf_append_byte(out, '\n');
    }
    free(tmp);
    return 0;
}

/* ================================================================== */
/* Hash primitives (MD5 / SHA-1 / SHA-256)                             */
/* ================================================================== */

static uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t load_le32(const uint8_t *p)
{
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* ---- MD5 ---------------------------------------------------------- */

static void md5_block(uint32_t st[4], const uint8_t *b)
{
    static const uint32_t K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
        0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
        0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
        0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
        0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
        0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
        0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
        0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    static const uint8_t S[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = load_le32(b + i * 4);

    uint32_t a = st[0], bb = st[1], c = st[2], d = st[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16) {
            f = (bb & c) | (~bb & d);
            g = i;
        } else if (i < 32) {
            f = (d & bb) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = bb ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (bb | ~d);
            g = (7 * i) % 16;
        }
        uint32_t tmp = d;
        d = c;
        c = bb;
        bb = bb + rotl32(a + f + K[i] + m[g], S[i]);
        a = tmp;
    }
    st[0] += a;
    st[1] += bb;
    st[2] += c;
    st[3] += d;
}

static void md5_hash(const uint8_t *msg, size_t len, uint8_t out[16])
{
    uint32_t st[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };
    size_t i = 0;
    for (; i + 64 <= len; i += 64)
        md5_block(st, msg + i);

    uint8_t tail[128];
    size_t rem = len - i;
    memcpy(tail, msg + i, rem);
    tail[rem] = 0x80;
    size_t padlen = rem < 56 ? 64 : 128;
    memset(tail + rem + 1, 0, padlen - rem - 1);
    uint64_t bits = (uint64_t)len * 8;
    store_le32(tail + padlen - 8, (uint32_t)bits);
    store_le32(tail + padlen - 4, (uint32_t)(bits >> 32));
    md5_block(st, tail);
    if (padlen == 128)
        md5_block(st, tail + 64);

    for (int j = 0; j < 4; j++)
        store_le32(out + j * 4, st[j]);
}

/* ---- SHA-1 -------------------------------------------------------- */

static void sha1_block(uint32_t st[5], const uint8_t *b)
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = load_be32(b + i * 4);
    for (int i = 16; i < 80; i++)
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = st[0], bb = st[1], c = st[2], d = st[3], e = st[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (bb & c) | (~bb & d);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = bb ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (bb & c) | (bb & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = bb ^ c ^ d;
            k = 0xca62c1d6u;
        }
        uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(bb, 30);
        bb = a;
        a = tmp;
    }
    st[0] += a;
    st[1] += bb;
    st[2] += c;
    st[3] += d;
    st[4] += e;
}

static void sha1_hash(const uint8_t *msg, size_t len, uint8_t out[20])
{
    uint32_t st[5] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu,
                       0x10325476u, 0xc3d2e1f0u };
    size_t i = 0;
    for (; i + 64 <= len; i += 64)
        sha1_block(st, msg + i);

    uint8_t tail[128];
    size_t rem = len - i;
    memcpy(tail, msg + i, rem);
    tail[rem] = 0x80;
    size_t padlen = rem < 56 ? 64 : 128;
    memset(tail + rem + 1, 0, padlen - rem - 1);
    uint64_t bits = (uint64_t)len * 8;
    store_be32(tail + padlen - 8, (uint32_t)(bits >> 32));
    store_be32(tail + padlen - 4, (uint32_t)bits);
    sha1_block(st, tail);
    if (padlen == 128)
        sha1_block(st, tail + 64);

    for (int j = 0; j < 5; j++)
        store_be32(out + j * 4, st[j]);
}

/* ---- SHA-256 ------------------------------------------------------ */

static void sha256_block(uint32_t st[8], const uint8_t *b)
{
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
        0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
        0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = load_be32(b + i * 4);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = st[0], bb = st[1], c = st[2], d = st[3];
    uint32_t e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & bb) ^ (a & c) ^ (bb & c);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = bb;
        bb = a;
        a = t1 + t2;
    }
    st[0] += a;
    st[1] += bb;
    st[2] += c;
    st[3] += d;
    st[4] += e;
    st[5] += f;
    st[6] += g;
    st[7] += h;
}

static void sha256_hash(const uint8_t *msg, size_t len, uint8_t out[32])
{
    uint32_t st[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                       0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    size_t i = 0;
    for (; i + 64 <= len; i += 64)
        sha256_block(st, msg + i);

    uint8_t tail[128];
    size_t rem = len - i;
    memcpy(tail, msg + i, rem);
    tail[rem] = 0x80;
    size_t padlen = rem < 56 ? 64 : 128;
    memset(tail + rem + 1, 0, padlen - rem - 1);
    uint64_t bits = (uint64_t)len * 8;
    store_be32(tail + padlen - 8, (uint32_t)(bits >> 32));
    store_be32(tail + padlen - 4, (uint32_t)bits);
    sha256_block(st, tail);
    if (padlen == 128)
        sha256_block(st, tail + 64);

    for (int j = 0; j < 8; j++)
        store_be32(out + j * 4, st[j]);
}

/* ================================================================== */
/* Hash brute force                                                    */
/* ================================================================== */

typedef void (*hash_fn_t)(const uint8_t *msg, size_t len, uint8_t *out);

typedef struct {
    const char *name;
    hash_fn_t   fn;
    size_t      digest_len;
} hash_def_t;

static const hash_def_t g_hashes[] = {
    { "md5",    md5_hash,    16 },
    { "sha1",   sha1_hash,   20 },
    { "sha256", sha256_hash, 32 },
};

static int name_eq_ci(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static const hash_def_t *hash_by_name(const char *name)
{
    for (size_t i = 0; i < sizeof g_hashes / sizeof g_hashes[0]; i++) {
        if (name_eq_ci(name, g_hashes[i].name))
            return &g_hashes[i];
    }
    /* A couple of common spellings of the same thing. */
    if (name_eq_ci(name, "sha-1"))
        return &g_hashes[1];
    if (name_eq_ci(name, "sha-256"))
        return &g_hashes[2];
    return NULL;
}

static int parse_hex_digest(const uint8_t *s, size_t n, uint8_t *out,
                            size_t outlen)
{
    size_t o = 0;
    int hi = -1;
    for (size_t i = 0; i < n; i++) {
        int c = s[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ':' ||
            c == '-')
            continue;
        int v = hex_nibble(c);
        if (v < 0)
            return -1;
        if (hi < 0) {
            hi = v;
        } else {
            if (o >= outlen)
                return -1;
            out[o++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0 || o != outlen)
        return -1;
    return 0;
}

typedef struct {
    const uint8_t   *alphabet;
    uint32_t         alen;
    uint32_t         word_len;
    const hash_def_t *hd;
    const uint8_t   *target;
    uint64_t         start;
    uint64_t         end;
    uint8_t         *word;
    volatile int    *stop;
    pthread_mutex_t *lock;
    uint8_t         *found;
} hash_task_t;

static void *hash_worker(void *arg)
{
    hash_task_t *t = arg;
    uint8_t digest[32];
    for (uint64_t idx = t->start; idx < t->end; idx++) {
        if (*t->stop)
            break;
        uint64_t v = idx;
        for (uint32_t pos = t->word_len; pos-- > 0;) {
            t->word[pos] = t->alphabet[v % t->alen];
            v /= t->alen;
        }
        t->hd->fn(t->word, t->word_len, digest);
        if (memcmp(digest, t->target, t->hd->digest_len) == 0) {
            pthread_mutex_lock(t->lock);
            if (!*t->stop) {
                memcpy(t->found, t->word, t->word_len);
                *t->stop = 1;
            }
            pthread_mutex_unlock(t->lock);
            break;
        }
    }
    return NULL;
}

static int hash_brute(const algo_params_t *p, buf_t *out)
{
    if (!p->hash || !*p->hash) {
        buf_append_str(out, "error: missing hash function\n");
        return -1;
    }
    const hash_def_t *hd = hash_by_name(p->hash);
    if (!hd) {
        buf_appendf(out, "error: unsupported hash function '%s'\n", p->hash);
        return -1;
    }

    uint8_t target[32];
    if (parse_hex_digest(p->input, p->input_len, target, hd->digest_len) != 0) {
        buf_appendf(out,
                    "error: target is not a valid %s digest (%zu hex bytes)\n",
                    hd->name, hd->digest_len);
        return -1;
    }

    if (!p->alphabet || p->alphabet_len == 0) {
        buf_append_str(out, "error: empty alphabet\n");
        return -1;
    }
    if (p->alphabet_len > 256) {
        buf_append_str(out, "error: alphabet larger than 256 symbols\n");
        return -1;
    }
    uint32_t alen = (uint32_t)p->alphabet_len;
    uint32_t wl = p->word_len;
    if (wl == 0) {
        buf_append_str(out, "error: word length must be at least 1\n");
        return -1;
    }
    if (wl > CTF_HASH_MAX_WORDLEN) {
        buf_appendf(out, "error: word length %u exceeds limit %u\n", wl,
                    CTF_HASH_MAX_WORDLEN);
        return -1;
    }

    uint64_t space = 1;
    for (uint32_t i = 0; i < wl; i++) {
        if (space > CTF_HASH_MAX_SPACE / alen) {
            buf_appendf(out,
                        "error: search space too large (alphabet %u, "
                        "length %u)\n",
                        alen, wl);
            return -1;
        }
        space *= alen;
    }

    unsigned nthreads = CTF_HASH_INNER_THREADS;
    if ((uint64_t)nthreads > space)
        nthreads = (unsigned)space;
    if (nthreads < 1)
        nthreads = 1;

    uint8_t found[CTF_HASH_MAX_WORDLEN];
    volatile int stop = 0;
    pthread_mutex_t lock;
    pthread_mutex_init(&lock, NULL);

    pthread_t tids[CTF_HASH_INNER_THREADS];
    hash_task_t tasks[CTF_HASH_INNER_THREADS];
    uint64_t chunk = (space + nthreads - 1) / nthreads;

    for (unsigned i = 0; i < nthreads; i++) {
        tasks[i].alphabet = p->alphabet;
        tasks[i].alen = alen;
        tasks[i].word_len = wl;
        tasks[i].hd = hd;
        tasks[i].target = target;
        tasks[i].start = (uint64_t)i * chunk;
        tasks[i].end = tasks[i].start + chunk;
        if (tasks[i].end > space)
            tasks[i].end = space;
        tasks[i].word = malloc(wl);
        tasks[i].stop = &stop;
        tasks[i].lock = &lock;
        tasks[i].found = found;
        tids[i] = 0;
        if (tasks[i].start >= tasks[i].end || !tasks[i].word)
            continue;
        if (pthread_create(&tids[i], NULL, hash_worker, &tasks[i]) != 0) {
            hash_worker(&tasks[i]);
        }
    }

    for (unsigned i = 0; i < nthreads; i++) {
        if (tids[i])
            pthread_join(tids[i], NULL);
        free(tasks[i].word);
    }
    pthread_mutex_destroy(&lock);

    char target_hex[65];
    hex_encode(target, hd->digest_len, target_hex);
    buf_appendf(out,
                "%s brute force: target=%s, alphabet=%u symbol(s), "
                "length=%u, space=%llu\n",
                hd->name, target_hex, alen, wl,
                (unsigned long long)space);
    if (stop) {
        buf_append_str(out, "MATCH: ");
        if (is_printable(found, wl)) {
            buf_append(out, found, wl);
        } else {
            char word_hex[CTF_HASH_MAX_WORDLEN * 2 + 1];
            hex_encode(found, wl, word_hex);
            buf_append_str(out, "0x");
            buf_append_str(out, word_hex);
        }
        buf_append_byte(out, '\n');
    } else {
        buf_append_str(out, "no match found\n");
    }
    return 0;
}

/* ================================================================== */
/* Registry                                                            */
/* ================================================================== */

static const algo_t g_algos[] = {
    { 1, "xor_brute",
      "XOR brute force (single and multi-byte keys, printable results)",
      xor_brute },
    { 2, "caesar_brute", "Caesar shift brute force (25 shifts)", caesar_brute },
    { 3, "rot13", "ROT13", rot13_run },
    { 4, "atbash", "Atbash substitution", atbash_run },
    { 5, "base64_encode", "Base64 encode", b64_encode_run },
    { 6, "base64_decode", "Base64 decode", b64_decode_run },
    { 7, "hex_encode", "Hex encode", hex_encode_run },
    { 8, "hex_decode", "Hex decode", hex_decode_run },
    { 9, "hash_brute",
      "Hash brute force (MD5/SHA-1/SHA-256, custom alphabet and length)",
      hash_brute },
};

const algo_t *algo_all(size_t *count)
{
    if (count)
        *count = sizeof g_algos / sizeof g_algos[0];
    return g_algos;
}

const algo_t *algo_by_id(uint16_t id)
{
    for (size_t i = 0; i < sizeof g_algos / sizeof g_algos[0]; i++)
        if (g_algos[i].id == id)
            return &g_algos[i];
    return NULL;
}

const algo_t *algo_by_name(const char *name)
{
    if (!name)
        return NULL;
    for (size_t i = 0; i < sizeof g_algos / sizeof g_algos[0]; i++)
        if (strcmp(g_algos[i].name, name) == 0)
            return &g_algos[i];
    return NULL;
}
