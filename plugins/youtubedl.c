
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <json-c/json.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include <event2/http.h>

#include "../common.h"
#include "../debug.h"
#include "../config.h"
#include "youtubedl.h"

struct yt_dlp_param {
    char    action[10];
    char    profile[100];
};

// define yt-dlp worker function
static void *
yt_dlp_worker(void *param)
{
    struct yt_dlp_param *p = (struct yt_dlp_param *)param;
    debug(LOG_DEBUG, "yt-dlp: action: %s, url: %s\n", p->action, p->profile);
    char cmd[512] = {0};

    // create directory yt-dlp and change current directory to it
    snprintf(cmd, sizeof(cmd), "mkdir -p yt-dlp && cd yt-dlp");
    debug(LOG_DEBUG, "yt-dlp: cmd: %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        debug(LOG_ERR, "yt-dlp: failed to execute command: %s, error: %d", cmd, ret);
    }

    if (strcmp(p->action, "download") == 0) {
        // download profile
        snprintf(cmd, sizeof(cmd), "yt-dlp %s", p->profile);
        debug(LOG_DEBUG, "yt-dlp: cmd: %s\n", cmd);
        // use popen to execute cmd and get its output
        FILE *fp = popen(cmd, "r");
        if (fp == NULL) {
            debug(LOG_ERR, "yt-dlp: popen failed\n");
            free(param);
            return NULL;
        }
        char buf[512] = {0};
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            debug(LOG_DEBUG, "yt-dlp: %s", buf);
            memset(buf, 0, sizeof(buf));
        }
        pclose(fp);
    } else {
        debug(LOG_ERR, "yt-dlp: unknown action: %s\n", p->action);
    }

    // free param
    free(param);

    return 0;
}

static int
parse_yt_dlp_command(char *json_data, struct yt_dlp_param *param)
{
    // parse json data with json-c to param
    json_object *jobj = json_tokener_parse(json_data);
    if (jobj == NULL) {
        debug(LOG_ERR, "yt-dlp: json_tokener_parse failed\n");
        return -1;
    }

    // get action
    json_object *jaction = NULL;
    if (!json_object_object_get_ex(jobj, "action", &jaction)) {
        debug(LOG_ERR, "yt-dlp: json_object_object_get_ex failed\n");
        json_object_put(jobj);
        return -1;
    }
    strcpy(param->action, json_object_get_string(jaction));
    if (strcmp(param->action, "stop") == 0) {
        json_object_put(jobj);
        return 0;
    }

    // get profile
    json_object *jprofile = NULL;
    if (!json_object_object_get_ex(jobj, "profile", &jprofile)) {
        debug(LOG_ERR, "yt-dlp: json_object_object_get_ex failed\n");
        json_object_put(jobj);
        return -1;
    }
    strcpy(param->profile, json_object_get_string(jprofile));

    // free json object
    json_object_put(jobj);

    return 0;
}

static void
yt_dlp_response(struct evhttp_request *req, char *result)
{
    struct evbuffer *resp = evbuffer_new();
    evbuffer_add_printf(resp, "{\"status\": \"%s\"}", result);
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", resp);
}

// define yt-dlp read callback function
static void
yt_dlp_read_cb(struct evhttp_request *req, void *args)
{
#define BUFF_LEN 4096
    // read data from bufferevent
    char data[BUFF_LEN] = {0};
    struct evbuffer *input = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(input);
    assert(len < BUFF_LEN);
    if (len >= BUFF_LEN) {
        debug(LOG_ERR, "yt-dlp: data length is too long\n");
        yt_dlp_response(req, "data length is too long");
        return;
    }
    debug(LOG_DEBUG, "yt-dlp: data: %s\n", data);

    // parse http post and get its json data
    evbuffer_copyout(input, data, len);
    debug(LOG_DEBUG, "yt-dlp: data: %s\n", data);

    struct yt_dlp_param *param = (struct yt_dlp_param *)malloc(sizeof(struct yt_dlp_param));
    assert(param != NULL);
    memset(param, 0, sizeof(struct yt_dlp_param));

    int nret = parse_yt_dlp_command (data, param);
    if (nret != 0) {
        debug(LOG_ERR, "yt-dlp: parse_command failed\n");
        free(param);
        yt_dlp_response(req, "failed to parse command");
        return;
    }

    // create a thread
    pthread_t thread;
    // create a thread attribute
    pthread_attr_t attr;
    // initialize thread attribute
    pthread_attr_init(&attr);
    // set thread attribute to detach
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    // create a thread
    pthread_create(&thread, &attr, yt_dlp_worker, param);
    // destroy thread attribute
    pthread_attr_destroy(&attr);

    yt_dlp_response(req, "ok");
}

// define yt-dlp http post callback function
static void
http_post_cb(struct evhttp_request *req, void *arg)
{
    // check http request method
    if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
        debug(LOG_ERR, "yt-dlp: http request method is not POST\n");
        evhttp_send_error(req, HTTP_BADMETHOD, "Method Not Allowed");
        return;
    }

    // Check the HTTP request content type
    const char *content_type = evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Type");
    if (content_type == NULL || strcmp(content_type, "application/json") != 0) {
        debug(LOG_ERR, "yt-dlp: http request content type is not application/json\n");
        evhttp_send_error(req, HTTP_BADREQUEST, "Bad Request");
        return;
    }

    // get json data from http request
    yt_dlp_read_cb(req, arg);

}

static int
install_yt_dlp()
{
    // if yt-dlp exists, return
    if (access("/usr/local/bin/yt-dlp", F_OK) == 0) {
        debug(LOG_DEBUG, "yt-dlp: yt-dlp exists\n");
        return 0;
    }

    // install yt-dlp to /usr/local/bin
    // download yt-dlp through curl or wget if any of them exists
    char cmd[512] = {0};
    if (access("/usr/bin/curl", F_OK) == 0) {
        snprintf(cmd, sizeof(cmd), "sudo curl -L https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp -o /usr/local/bin/yt-dlp");
    } else if (access("/usr/bin/wget", F_OK) == 0) {
        snprintf(cmd, sizeof(cmd), "sudo wget https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp -O /usr/local/bin/yt-dlp");
    } else {
        debug(LOG_ERR, "yt-dlp: curl and wget are not installed\n");
        return -1;
    }
    debug(LOG_DEBUG, "yt-dlp: cmd: %s\n", cmd);
    int nret = system(cmd);
    if (nret != 0) {
        debug(LOG_ERR, "yt-dlp: system failed\n");
        return -1;
    }
    // change yt-dlp to executable
    snprintf(cmd, sizeof(cmd), "sudo chmod a+rx /usr/local/bin/yt-dlp");
    debug(LOG_DEBUG, "yt-dlp: cmd: %s\n", cmd);
    nret = system(cmd);
    if (nret != 0) {
        debug(LOG_ERR, "yt-dlp: system failed\n");
        return -1;
    }
    
    return 0;
}

// define yt-dlp service
static void *
yt_dlp_service(void *local_port)
{
    // install yt-dlp
    int nret = install_yt_dlp();
    if (nret != 0) {
        debug(LOG_ERR, "yt-dlp: install_yt_dlp failed\n");
        return NULL;
    }

    uint16_t port = *(uint16_t *)local_port;
    free(local_port);
    // Initialize libevent
    struct event_base *base = event_base_new();
    if (!base) {
        debug(LOG_ERR, "yt-dlp: Failed to initialize libevent\n");
        return NULL;
    }

    // Create a new HTTP server
    struct evhttp *http = evhttp_new(base);
    if (!http) {
        debug(LOG_ERR, "yt-dlp: Failed to create HTTP server\n");
        return NULL;
    }


    if (evhttp_bind_socket(http, "0.0.0.0", port) != 0) {
        debug(LOG_ERR, "yt-dlp: Failed to bind HTTP server to port %d\n", port);
        return NULL;
    }

    debug(LOG_DEBUG, "yt-dlp: start youtube download service on port %d\n", port);

    // Set up a callback function for handling HTTP requests
    evhttp_set_cb(http, "/", http_post_cb, NULL);

    // Start the event loop
    event_base_dispatch(base);

    // Clean up
    evhttp_free(http);
    event_base_free(base);
    return NULL;
}

int
start_youtubedl_service(uint16_t local_port)
{
    uint16_t *p = (uint16_t *)malloc(sizeof(uint16_t));
    assert(p != NULL);
    *p = local_port;
    // create a thread
    pthread_t thread;
    // create a thread attribute
    pthread_attr_t attr;
    // initialize thread attribute
    pthread_attr_init(&attr);
    // set thread attribute to detach
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    // create a thread
    pthread_create(&thread, &attr, yt_dlp_service, (void *)p);
    // destroy thread attribute
    pthread_attr_destroy(&attr);

    return 0;
}
