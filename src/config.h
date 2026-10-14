#ifndef CTF_CONFIG_H
#define CTF_CONFIG_H

/*
 * Central build/runtime configuration for the CTF tool.
 *
 * Everything that a system administrator or a developer may want to tune
 * without touching module internals lives here.  Modules must include this
 * header instead of hard coding magic numbers.
 */

/* ------------------------------------------------------------------ */
/* Networking                                                          */
/* ------------------------------------------------------------------ */

#define CTF_WEB_BIND        "127.0.0.1"
#define CTF_WEB_PORT        8080

#define CTF_LOGIC_BIND      "127.0.0.1"
#define CTF_LOGIC_PORT      9090

/* Where the web server looks for the logic server. */
#define CTF_LOGIC_HOST      "127.0.0.1"

#define CTF_LISTEN_BACKLOG  128

/* ------------------------------------------------------------------ */
/* Static assets                                                       */
/* ------------------------------------------------------------------ */

/* Directory (relative to the process working directory unless an
 * absolute path / -t override is supplied) that holds the SPA pages. */
#define CTF_TEMPLATES_DIR   "src/templates"

/* Largest static file we are willing to keep in memory. */
#define CTF_MAX_FILE_BYTES  (8u * 1024u * 1024u)

/* ------------------------------------------------------------------ */
/* Protocol                                                            */
/* ------------------------------------------------------------------ */

#define CTF_PROTO_VERSION   1u
/* Maximum size of a single protocol payload (defensive limit). */
#define CTF_PROTO_MAX_PAYLOAD (4u * 1024u * 1024u)

/* ------------------------------------------------------------------ */
/* Limits                                                              */
/* ------------------------------------------------------------------ */

/* Largest HTTP request (headers + body) accepted. */
#define CTF_MAX_HTTP_REQUEST (1u * 1024u * 1024u)
/* Largest user supplied input (the string we operate on). */
#define CTF_MAX_INPUT_BYTES  (256u * 1024u)
/* Longest key the XOR brute forcer will attempt. */
#define CTF_XOR_MAX_KEYLEN   3

/* ------------------------------------------------------------------ */
/* Logic server                                                        */
/* ------------------------------------------------------------------ */

/* Number of worker threads cracking jobs in parallel. */
#define CTF_LOGIC_WORKERS    4
/* Number of worker threads used *inside* a single heavy brute force. */
#define CTF_XOR_INNER_THREADS 4

/* How long a finished job stays queryable from the web layer (ms). */
#define CTF_JOB_TTL_MS       (10u * 60u * 1000u)
/* Number of buckets in the web layer job hash table (power of two). */
#define CTF_JOB_BUCKETS      1024

/* Reconnect backoff for the web -> logic link. */
#define CTF_LOGIC_RECONNECT_MS 1000

#endif /* CTF_CONFIG_H */
