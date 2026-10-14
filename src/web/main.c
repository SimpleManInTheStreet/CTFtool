#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/util.h"
#include "config.h"
#include "web/web.h"

static web_server_t *g_srv = NULL;
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
            "  -b, --bind ADDR       HTTP bind address (default %s)\n"
            "  -p, --port PORT       HTTP port         (default %d)\n"
            "  -l, --logic-host HOST logic server host (default %s)\n"
            "  -L, --logic-port PORT logic server port (default %d)\n"
            "  -t, --templates DIR   templates directory (default %s)\n"
            "  -v, --verbose         debug logging\n"
            "  -h, --help            this help\n",
            prog, CTF_WEB_BIND, CTF_WEB_PORT, CTF_LOGIC_HOST, CTF_LOGIC_PORT,
            CTF_TEMPLATES_DIR);
}

int main(int argc, char **argv)
{
    const char *bind = CTF_WEB_BIND;
    int port = CTF_WEB_PORT;
    const char *logic_host = CTF_LOGIC_HOST;
    int logic_port = CTF_LOGIC_PORT;
    const char *templates = CTF_TEMPLATES_DIR;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bind")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            bind = argv[i];
        } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            port = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--logic-host")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            logic_host = argv[i];
        } else if (!strcmp(argv[i], "-L") || !strcmp(argv[i], "--logic-port")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            logic_port = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--templates")) {
            if (++i >= argc) { usage(argv[0]); return 2; }
            templates = argv[i];
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

    if (web_server_start(&g_srv, bind, port, logic_host, logic_port,
                         templates) != 0) {
        log_error("main", "failed to start web server");
        return 1;
    }

    while (!g_stop)
        pause();

    log_info("main", "shutting down");
    web_server_stop(g_srv);
    g_srv = NULL;
    return 0;
}
