#ifndef CTF_WEB_H
#define CTF_WEB_H

/*
 * WEB - local HTTP server for the CTF tool.
 *
 * Responsibilities
 *   - serve the static single page application from templates/
 *   - expose a small JSON API used by that SPA
 *   - keep one persistent PROTO connection to the LOGIC server
 *   - remember every in-flight calculation so that late results can be
 *     correlated back to the browser request that asked for them
 *
 * The web server never runs cracking code itself; it is a thin, async
 * front end in front of the logic server.
 */

typedef struct web_server web_server_t;

int web_server_start(web_server_t **out, const char *bind_addr, int port,
                     const char *logic_host, int logic_port,
                     const char *templates_dir);

void web_server_stop(web_server_t *srv);

#endif /* CTF_WEB_H */
