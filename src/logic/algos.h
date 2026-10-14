#ifndef CTF_LOGIC_ALGOS_H
#define CTF_LOGIC_ALGOS_H

/*
 * Algorithm registry for the LOGIC module.
 *
 * A "cracking algorithm" is a pure function.  It receives the user input
 * plus a few generic parameters and appends human readable, UTF-8 text to
 * an output buffer.  Algorithms never touch sockets or global state, which
 * makes them trivially safe to run from any worker thread.
 */

#include <stddef.h>
#include <stdint.h>

#include "common/util.h"

typedef struct {
    const uint8_t *input;
    size_t         input_len;
    uint32_t       key_len;  /* algorithm specific, e.g. XOR key length */
    uint32_t       flags;    /* algorithm specific bit flags            */
} algo_params_t;

typedef struct {
    uint16_t    id;
    const char *name;
    const char *description;
    /* Returns 0 on success, -1 on error and appends a message to `out`. */
    int (*run)(const algo_params_t *p, buf_t *out);
} algo_t;

const algo_t *algo_by_id(uint16_t id);
const algo_t *algo_by_name(const char *name);
const algo_t *algo_all(size_t *count);

#endif /* CTF_LOGIC_ALGOS_H */
