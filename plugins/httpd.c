
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <pthread.h>

#include "../debug.h"
#include "../mongoose.h"
#include "httpd.h"

static const char *s_root_dir = ".";
static const char *s_listening_address = "http://0.0.0.0:8000";

static void
httpd_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data)
{
    if (ev == MG_EV_HTTP_MSG)
    {
        struct mg_http_message *hm = ev_data, tmp = {0};
        struct mg_str unknown = mg_str_n("?", 1), *cl;
        struct mg_http_serve_opts opts = {0};
        opts.root_dir = s_root_dir;
        mg_http_serve_dir(c, hm, &opts);
        mg_http_parse((char *)c->send.buf, c->send.len, &tmp);
        cl = mg_http_get_header(&tmp, "Content-Length");
        if (cl == NULL)
            cl = &unknown;
        debug(LOG_INFO, "HTTP: %.*s %.*s %.*s %.*s\n",
              (int)hm->method.len, hm->method.ptr,
              (int)hm->uri.len, hm->uri.ptr,
              (int)tmp.uri.len, tmp.uri.ptr,
              (int)cl->len, cl->ptr);
    }
    (void)fn_data;
}

static void *
httpd_thread(void *arg)
{
    char path[MG_PATH_MAX] = ".";
    struct mg_mgr mgr;
    struct mg_connection *c;
    struct proxy_service *ps = (struct proxy_service *)arg;

    mg_mgr_init(&mgr);
    if ((c = mg_http_listen(&mgr, s_listening_address, httpd_handler, &mgr)) == NULL)
    {
        debug(LOG_ERR, "Cannot listen on %s. Use http://ADDR:PORT or :PORT",
              s_listening_address);
        exit(EXIT_FAILURE);
    }

    // Root directory must not contain double dots. Make it absolute
    // Do the conversion only if the root dir spec does not contain overrides
    if (strchr(ps->s_root_dir, ',') == NULL)
    {
        realpath(ps->s_root_dir, path);
        s_root_dir = path;
    }

    debug(LOG_INFO, "Listening on     : %s", s_listening_address);
    debug(LOG_INFO, "Web root         : [%s]", s_root_dir);
    while (1)
        mg_mgr_poll(&mgr, 1000);
    mg_mgr_free(&mgr);
    return NULL;
}

void start_httpd_service(struct proxy_service *ps)
{
    // start a httpd service in a new thread
    pthread_t thread;

    if (pthread_create(&thread, NULL, httpd_thread, ps) != 0)
    {
        debug(LOG_ERR, "Failed to create thread\n");
        exit(-1);
    }

    //detach thread
    pthread_detach(thread);
    

    return;
}