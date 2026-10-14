#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/util.h"
#include "config.h"
#include "logic/logic.h"

static logic_server_t *g_srv = NULL;
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [options]\n"
            "  -b, --bind ADDR     bind address (default %s)\n"
            "  -p, --port PORT     listen port  (default %d)\n"
            "  -w, --workers N     worker threads (default %d)\n"
            "  -v, --verbose       debug logging\n"
            "  -h, --help          this help\n",
            prog, CTF_LOGIC_BIND, CTF_LOGIC_PORT, CTF_LOGIC_WORKERS);
}

int main(int argc, char **argv)
{
    const char *bind = CTF_LOGIC_BIND;
    int port = CTF_LOGIC_PORT;
    int workers = CTF_LOGIC_WORKERS;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bind")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            bind = argv[i];
        } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            port = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-w") || !strcmp(argv[i], "--workers")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            workers = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            log_set_level(LOG_DEBUG);
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (logic_server_start(&g_srv, bind, port, workers) != 0) {
        log_error("main", "failed to start logic server");
        return 1;
    }

    while (!g_stop)
        pause();

    log_info("main", "shutting down");
    logic_server_stop(g_srv);
    g_srv = NULL;
    return 0;
}
