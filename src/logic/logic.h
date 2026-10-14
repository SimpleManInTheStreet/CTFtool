#ifndef CTF_LOGIC_H
#define CTF_LOGIC_H

/*
 * LOGIC - asynchronous calculation server.
 *
 * The logic server listens on its own TCP port and speaks PROTO.  A client
 * (normally the WEB module) opens one long lived connection and pushes
 * calculation requests.  Each request carries a caller chosen request id.
 * Jobs are dispatched onto a worker pool so the connection keeps accepting
 * new requests while earlier ones are still being cracked.  When a job
 * finishes the result is pushed back over the same connection tagged with
 * the original request id.
 */

typedef struct logic_server logic_server_t;

/* Creates the listener, spins up the worker pool and the accept loop.
 * Returns 0 on success; on failure -1 and no resources are leaked. */
int logic_server_start(logic_server_t **out, const char *bind_addr, int port,
                       int workers);

/* Signals all threads to stop and releases every resource. */
void logic_server_stop(logic_server_t *srv);

#endif /* CTF_LOGIC_H */
