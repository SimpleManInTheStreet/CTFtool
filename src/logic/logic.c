#define _GNU_SOURCE
#include "logic/logic.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/util.h"
#include "config.h"
#include "logic/algos.h"
#include "proto/proto.h"

#define MOD "logic"

/* ================================================================== */
/* Connection                                                          */
/* ================================================================== */

typedef struct logic_server logic_server_t;

typedef struct conn {
    int             fd;
    logic_server_t *srv;
    pthread_mutex_t wlock; /* serialises writes to fd                  */
    pthread_mutex_t rlock; /* guards refs                              */
    int             refs;  /* reader + in-flight jobs                  */
} conn_t;

static void conn_ref(conn_t *c)
{
    pthread_mutex_lock(&c->rlock);
    c->refs++;
    pthread_mutex_unlock(&c->rlock);
}

static void conn_unref(conn_t *c)
{
    int dead;
    pthread_mutex_lock(&c->rlock);
    dead = (--c->refs == 0);
    pthread_mutex_unlock(&c->rlock);
    if (dead) {
        close(c->fd);
        pthread_mutex_destroy(&c->wlock);
        pthread_mutex_destroy(&c->rlock);
        free(c);
    }
}

static int conn_send(conn_t *c, const proto_msg_t *m)
{
    pthread_mutex_lock(&c->wlock);
    int rc = proto_send(c->fd, m);
    pthread_mutex_unlock(&c->wlock);
    return rc;
}

/* ================================================================== */
/* Job queue                                                           */
/* ================================================================== */

typedef struct job {
    conn_t      *conn;
    proto_msg_t *req;
    struct job  *next;
} job_t;

typedef struct {
    job_t          *head;
    job_t          *tail;
    pthread_mutex_t lock;
    pthread_cond_t  cv;
    int             stop;
} jobq_t;

static void jobq_init(jobq_t *q)
{
    q->head = q->tail = NULL;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cv, NULL);
    q->stop = 0;
}

static void jobq_push(jobq_t *q, job_t *j)
{
    j->next = NULL;
    pthread_mutex_lock(&q->lock);
    if (q->tail)
        q->tail->next = j;
    else
        q->head = j;
    q->tail = j;
    pthread_cond_signal(&q->cv);
    pthread_mutex_unlock(&q->lock);
}

static job_t *jobq_pop(jobq_t *q)
{
    pthread_mutex_lock(&q->lock);
    while (!q->head && !q->stop)
        pthread_cond_wait(&q->cv, &q->lock);
    job_t *j = q->head;
    if (j) {
        q->head = j->next;
        if (!q->head)
            q->tail = NULL;
    }
    pthread_mutex_unlock(&q->lock);
    return j;
}

static void jobq_stop(jobq_t *q)
{
    pthread_mutex_lock(&q->lock);
    q->stop = 1;
    pthread_cond_broadcast(&q->cv);
    pthread_mutex_unlock(&q->lock);
}

/* ================================================================== */
/* Server                                                              */
/* ================================================================== */

struct logic_server {
    int             listen_fd;
    volatile int    running;
    int             workers;
    pthread_t       accept_thread;
    pthread_t      *pool;
    jobq_t          queue;
};

/* Run one request and answer it. */
static void process_job(logic_server_t *srv, job_t *job)
{
    (void)srv;
    const proto_msg_t *req = job->req;

    uint64_t req_id = 0;
    uint32_t algo_id = 0;
    uint32_t key_len = 1;
    uint32_t flags = 0;
    proto_get_u64(req, PROTO_TAG_REQ_ID, &req_id);
    proto_get_u32(req, PROTO_TAG_ALGO, &algo_id);
    proto_get_u32(req, PROTO_TAG_KEY_LEN, &key_len);
    proto_get_u32(req, PROTO_TAG_FLAGS, &flags);

    uint32_t in_len = 0;
    const void *in = proto_get(req, PROTO_TAG_INPUT, &in_len);

    proto_msg_t *res = proto_msg_new(PROTO_CALC_RES);
    if (!res)
        goto cleanup;
    proto_add_u64(res, PROTO_TAG_REQ_ID, req_id);

    const algo_t *algo = algo_by_id((uint16_t)algo_id);
    if (!algo) {
        proto_add_u32(res, PROTO_TAG_STATUS, PROTO_STATUS_ERROR);
        proto_add_str(res, PROTO_TAG_ERROR, "unknown algorithm id");
        goto send;
    }
    if (!in) {
        proto_add_u32(res, PROTO_TAG_STATUS, PROTO_STATUS_ERROR);
        proto_add_str(res, PROTO_TAG_ERROR, "missing input");
        goto send;
    }
    if (in_len > CTF_MAX_INPUT_BYTES) {
        proto_add_u32(res, PROTO_TAG_STATUS, PROTO_STATUS_ERROR);
        proto_add_str(res, PROTO_TAG_ERROR, "input too large");
        goto send;
    }

    algo_params_t params = {
        .input = in,
        .input_len = in_len,
        .key_len = key_len,
        .flags = flags,
    };

    buf_t out;
    buf_init(&out);
    log_info(MOD, "job %llu: running %s (%u bytes)",
             (unsigned long long)req_id, algo->name, in_len);
    int rc = algo->run(&params, &out);

    if (rc != 0)
        proto_add_u32(res, PROTO_TAG_STATUS, PROTO_STATUS_ERROR);
    else
        proto_add_u32(res, PROTO_TAG_STATUS, PROTO_STATUS_OK);
    proto_add(res, PROTO_TAG_RESULT, out.data, (uint32_t)out.len);
    buf_free(&out);

send:
    if (conn_send(job->conn, res) != 0)
        log_warn(MOD, "job %llu: failed to deliver result",
                 (unsigned long long)req_id);
    proto_msg_free(res);

cleanup:
    proto_msg_free(job->req);
    conn_unref(job->conn);
    free(job);
}

static void *worker_main(void *arg)
{
    logic_server_t *srv = arg;
    for (;;) {
        job_t *j = jobq_pop(&srv->queue);
        if (!j)
            break; /* stop requested and queue drained */
        process_job(srv, j);
    }
    return NULL;
}

static void *conn_reader(void *arg)
{
    conn_t *c = arg;
    logic_server_t *srv = c->srv;

    proto_msg_t *msg = NULL;
    while (srv->running && proto_recv(c->fd, &msg) == 0) {
        int enqueued = 0;
        switch (msg->type) {
        case PROTO_HELLO: {
            uint32_t peer_ver = 0;
            proto_get_u32(msg, PROTO_TAG_VERSION, &peer_ver);
            proto_msg_t *ack = proto_msg_new(PROTO_HELLO_ACK);
            proto_add_u32(ack, PROTO_TAG_VERSION, PROTO_VERSION);
            proto_add_str(ack, PROTO_TAG_MESSAGE, "logic server ready");
            conn_send(c, ack);
            proto_msg_free(ack);
            log_info(MOD, "client handshake (protocol v%u)", peer_ver);
            break;
        }
        case PROTO_PING: {
            proto_msg_t *pong = proto_msg_new(PROTO_PONG);
            conn_send(c, pong);
            proto_msg_free(pong);
            break;
        }
        case PROTO_ALGO_LIST: {
            proto_msg_t *r = proto_msg_new(PROTO_ALGO_LIST_RES);
            size_t n = 0;
            const algo_t *all = algo_all(&n);
            if (r) {
                for (size_t i = 0; i < n; i++) {
                    proto_add_u32(r, PROTO_TAG_ALGO, all[i].id);
                    proto_add_str(r, PROTO_TAG_ALGO_NAME, all[i].name);
                    proto_add_str(r, PROTO_TAG_ALGO_DESC, all[i].description);
                }
                conn_send(c, r);
                proto_msg_free(r);
            }
            break;
        }
        case PROTO_CALC_REQ: {
            job_t *j = calloc(1, sizeof *j);
            if (j) {
                conn_ref(c);
                j->conn = c;
                j->req = msg;      /* ownership moves to the job */
                enqueued = 1;
                jobq_push(&srv->queue, j);
            } else {
                proto_msg_t *err = proto_msg_new(PROTO_ERROR);
                proto_add_str(err, PROTO_TAG_ERROR, "server out of memory");
                conn_send(c, err);
                proto_msg_free(err);
            }
            break;
        }
        case PROTO_BYE:
            proto_msg_free(msg);
            msg = NULL;
            goto done;
        default:
            break;
        }
        if (!enqueued)
            proto_msg_free(msg);
        msg = NULL;
    }

done:
    log_info(MOD, "client disconnected");
    conn_unref(c);
    return NULL;
}

static void *accept_main(void *arg)
{
    logic_server_t *srv = arg;
    while (srv->running) {
        int fd = accept(srv->listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            if (!srv->running)
                break;
            log_warn(MOD, "accept: %s", strerror(errno));
            continue;
        }

        conn_t *c = calloc(1, sizeof *c);
        if (!c) {
            close(fd);
            continue;
        }
        c->fd = fd;
        c->srv = srv;
        c->refs = 1;
        pthread_mutex_init(&c->wlock, NULL);
        pthread_mutex_init(&c->rlock, NULL);

        pthread_t t;
        if (pthread_create(&t, NULL, conn_reader, c) != 0) {
            log_error(MOD, "cannot spawn connection thread");
            close(fd);
            free(c);
            continue;
        }
        pthread_detach(t);
    }
    return NULL;
}

int logic_server_start(logic_server_t **out, const char *bind_addr, int port,
                       int workers)
{
    logic_server_t *srv = calloc(1, sizeof *srv);
    if (!srv)
        return -1;

    if (workers < 1)
        workers = 1;
    srv->workers = workers;
    srv->running = 1;

    srv->listen_fd = make_tcp_listener(bind_addr, port, CTF_LISTEN_BACKLOG);
    if (srv->listen_fd < 0)
        goto fail;

    jobq_init(&srv->queue);

    srv->pool = calloc((size_t)workers, sizeof(pthread_t));
    if (!srv->pool)
        goto fail;

    for (int i = 0; i < workers; i++) {
        if (pthread_create(&srv->pool[i], NULL, worker_main, srv) != 0) {
            log_error(MOD, "cannot spawn worker %d", i);
            srv->workers = i;
            goto fail;
        }
    }

    if (pthread_create(&srv->accept_thread, NULL, accept_main, srv) != 0) {
        log_error(MOD, "cannot spawn accept thread");
        goto fail;
    }

    log_info(MOD, "listening on %s:%d with %d workers",
             bind_addr ? bind_addr : "*", port, workers);
    *out = srv;
    return 0;

fail:
    srv->running = 0;
    if (srv->listen_fd >= 0)
        close(srv->listen_fd);
    free(srv->pool);
    free(srv);
    return -1;
}

void logic_server_stop(logic_server_t *srv)
{
    if (!srv)
        return;
    srv->running = 0;
    if (srv->listen_fd >= 0)
        shutdown(srv->listen_fd, SHUT_RDWR);
    pthread_join(srv->accept_thread, NULL);
    jobq_stop(&srv->queue);
    for (int i = 0; i < srv->workers; i++)
        pthread_join(srv->pool[i], NULL);
    if (srv->listen_fd >= 0)
        close(srv->listen_fd);
    free(srv->pool);
    free(srv);
}
