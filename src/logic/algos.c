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
