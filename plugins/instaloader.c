#include <json-c/json.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>


#include "../common.h"
#include "../debug.h"
#include "../config.h"
#include "instaloader.h"

struct instaloader_param {
    char    action[10];
    char    profile[100];
};

// define instaloader worker function
static void *
instaloader_worker(void *param)
{
    struct instaloader_param *p = (struct instaloader_param *)param;
    debug(LOG_DEBUG, "instaloader: action: %s, profile: %s\n", p->action, p->profile);
    char cmd[200] = {0};
    if (strcmp(p->action, "download") == 0) {
        // download profile
        snprintf(cmd, 200, "instaloader %s", p->profile);
        debug(LOG_DEBUG, "instaloader: cmd: %s\n", cmd);
        system(cmd);
    } else if (strcmp(p->action, "download_videos") == 0) {
        // download videos
        snprintf(cmd, 200, "instaloader --no-pictures %s", p->profile);
        debug(LOG_DEBUG, "instaloader: cmd: %s\n", cmd);
        system(cmd);
    } else if (strcmp(p->action, "download_pictures") == 0) {
        // download pictures
        snprintf(cmd, 200, "instaloader --no-videos %s", p->profile);
        debug(LOG_DEBUG, "instaloader: cmd: %s\n", cmd);
        system(cmd);
    } else {
        debug(LOG_ERR, "instaloader: unknown action: %s\n", p->action);
    }


    // free param
    free(param);

    return 0;
}

static int
parse_instaloader_command(char *json_data, struct instaloader_param *param)
{
    // parse json data with json-c to param
    json_object *jobj = json_tokener_parse(json_data);
    if (jobj == NULL) {
        debug(LOG_ERR, "instaloader: json_tokener_parse failed\n");
        return -1;
    }

    // get action
    json_object *jaction = NULL;
    if (json_object_object_get_ex(jobj, "action", &jaction) == FALSE) {
        debug(LOG_ERR, "instaloader: json_object_object_get_ex failed\n");
        json_object_put(jobj);
        return -1;
    }
    strcpy(param->action, json_object_get_string(jaction));

    // get profile
    json_object *jprofile = NULL;
    if (json_object_object_get_ex(jobj, "profile", &jprofile) == FALSE) {
        debug(LOG_ERR, "instaloader: json_object_object_get_ex failed\n");
        json_object_put(jobj);
        return -1;
    }
    strcpy(param->profile, json_object_get_string(jprofile));

    // free json object
    json_object_put(jobj);

    return 0;
}

static void
instaloader_response(struct bufferevent *bev, char *result)
{
    char resp[128] = {0};
    snprintf(resp, 128, "{\"status\": \"%s\"}", result);
    bufferevent_write(bev, resp, strlen(resp));
}

// define instaloader read callback function
static void
instaloader_read_cb(struct bufferevent *bev, void *ctx)
{
#define BUFF_LEN 4096
    // read data from bufferevent
    char data[BUFF_LEN] = {0};
    int nret = bufferevent_read(bev, data, sizeof(data));
    if (nret <= 0) {
        debug(LOG_ERR, "instaloader: bufferevent_read failed\n");
        instaloader_response(bev, "failed to read data");
        bufferevent_free(bev);
        return;
    }
    debug(LOG_DEBUG, "instaloader: data: %s\n", data);

    struct instaloader_param *param = (struct instaloader_param *)malloc(sizeof(struct instaloader_param));
    assert(param != NULL);
    memset(param, 0, sizeof(struct instaloader_param));

    nret = parse_instaloader_command(data, param);
    if (nret != 0) {
        debug(LOG_ERR, "instaloader: parse_command failed\n");
        free(param);
        instaloader_response(bev, "failed to parse command");
        bufferevent_free(bev);
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
    pthread_create(&thread, &attr, instaloader_worker, param);
    // destroy thread attribute
    pthread_attr_destroy(&attr);

    instaloader_response(bev, "ok");

    // close bufferevent
    bufferevent_free(bev);
}

// define instaloader event callback function
static void
instaloader_event_cb(struct bufferevent *bev, short events, void *ctx)
{
    if (events & BEV_EVENT_ERROR) {
        debug(LOG_ERR, "instaloader: Error from bufferevent\n");
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
    }
}

// Callback function for handling new connections
static void 
accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx)
{
    debug(LOG_DEBUG, "instaloader: accept_conn_cb\n");
    // Create a new bufferevent for the connection
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

    // Set up callbacks for the bufferevent
    bufferevent_setcb(bev, instaloader_read_cb, NULL, instaloader_event_cb, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

// Callback function for handling errors on the listener
static void 
accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    debug(LOG_ERR, "instaloader: Got an error %d (%s) on the listener. Shutting down.\n", err, evutil_socket_error_to_string(err));
    event_base_loopexit(base, NULL);
}

// define instaloader service
static void *
instaloader_service(void *local_port)
{
    uint16_t port = *(uint16_t *)local_port;
    free(local_port);
    // Initialize libevent
    struct event_base *base = event_base_new();
    if (!base) {
        debug(LOG_ERR, "instaloader: Failed to initialize libevent\n");
        return NULL;
    }

    // Create a new listener for incoming connections
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(port);

    struct evconnlistener *listener = evconnlistener_new_bind(base, accept_conn_cb, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, (struct sockaddr *)&sin, sizeof(sin));
    if (!listener) {
        debug(LOG_ERR, "instaloader: Failed to create listener\n");
        event_base_free(base);
        return NULL;
    }

    // Set up error handling for the listener
    evconnlistener_set_error_cb(listener, accept_error_cb);

    // Start the event loop
    event_base_dispatch(base);

    // Clean up
    evconnlistener_free(listener);
    event_base_free(base);

    return NULL;
}


int 
start_instaloader_service(uint16_t local_port)
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
    pthread_create(&thread, &attr, instaloader_service, (void *)p);
    // destroy thread attribute
    pthread_attr_destroy(&attr);

    return 0;
}