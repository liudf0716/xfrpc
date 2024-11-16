/*
 * Copyright (C) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <pthread.h>
#include <arpa/inet.h>

#include "common.h"
#include "debug.h"
#include "config.h"
#include "utils.h"
#include "tcp_redir.h"

/**
 * @brief Structure for TCP redirection service
 */
struct tcp_redir_service {
    struct event_base *base;        /**< libevent base for event handling */
    struct proxy_service *ps;       /**< proxy service configuration */ 
    struct sockaddr_in server_addr; /**< server address information */
};

static struct bufferevent *current_bev = NULL; // Global variable to hold the current connection

/**
 * @brief Read callback function for handling incoming data
 *
 * This callback function is triggered when data is received on the local connection.
 * It reads the data from the input buffer and writes it to the output buffer.
 *
 * @param bev The bufferevent that triggered the callback
 * @param arg The partner bufferevent
 */
static void read_cb(struct bufferevent *bev, void *arg)
{
    if (!bev || !arg) {
        debug(LOG_ERR, "Invalid bufferevent parameters");
        return;
    }

    struct bufferevent *bev_out = (struct bufferevent *)arg;
    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev_out);

    if (!input || !output) {
        debug(LOG_ERR, "Failed to get buffers");
        return;
    }

    size_t len = evbuffer_get_length(input);
    if (len > 0) {
        if (evbuffer_add_buffer(output, input) < 0) {
            debug(LOG_ERR, "Failed to transfer buffer data");
            return;
        }
        debug(LOG_DEBUG, "Transferred %zu bytes", len);
    }
}

/**
 * @brief Event callback function for handling bufferevent state changes
 *
 * @param bev The bufferevent that triggered the callback
 * @param events The events that occurred
 * @param arg The partner bufferevent
 */
static void event_cb(struct bufferevent *bev, short events, void *arg)
{
    struct bufferevent *partner = arg;
    
    if (!bev || !partner) {
        debug(LOG_ERR, "Invalid bufferevent parameters");
        return;
    }

    if (events & BEV_EVENT_CONNECTED) {
        debug(LOG_INFO, "Connection established successfully");
        return;
    }

    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        const char *msg = (events & BEV_EVENT_ERROR) ? 
                         "Connection error occurred" : 
                         "Connection closed by peer";
        debug(LOG_INFO, "%s", msg);

        if (current_bev) {
            bufferevent_free(bev);
            bufferevent_free(partner);
            current_bev = NULL;
        }
    }
}

/**
 * @brief Callback function for accepting new TCP connections
 *
 * This callback is triggered when a new TCP connection is received. It handles the following:
 * - Checks if there's already an existing connection (only one allowed)
 * - Creates bufferevent for the local connection
 * - Creates bufferevent for the remote connection
 * - Establishes connection to the remote server
 * - Sets up callbacks and enables events for both local and remote bufferevents
 *
 * @param listener The event listener that received the connection
 * @param fd The socket file descriptor for the new connection
 * @param address The address structure of the connecting client
 * @param socklen The length of the address structure
 * @param arg User-provided argument (tcp_redir_service structure)
 *
 * @note This implementation only allows one active connection at a time
 */
static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *address, int socklen, void *arg)
{
    struct tcp_redir_service *trs = (struct tcp_redir_service *)arg;
    struct bufferevent *bev_in = NULL, *bev_out = NULL;

    // Check for existing connection
    if (current_bev) {
        debug(LOG_INFO, "Rejecting new connection: only one connection allowed");
        evutil_closesocket(fd);
        return;
    }

    // Create local bufferevent
    bev_in = bufferevent_socket_new(trs->base, fd, 
                                   BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    if (!bev_in) {
        debug(LOG_ERR, "Failed to create local bufferevent");
        evutil_closesocket(fd);
        return;
    }

    // Create remote bufferevent
    bev_out = bufferevent_socket_new(trs->base, -1, 
                                    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    if (!bev_out) {
        debug(LOG_ERR, "Failed to create remote bufferevent");
        bufferevent_free(bev_in);
        return;
    }

    // Connect to remote server
    if (bufferevent_socket_connect(bev_out, (struct sockaddr *)&(trs->server_addr), 
                                  sizeof(trs->server_addr)) < 0) {
        debug(LOG_ERR, "Failed to connect to remote server: %s", strerror(errno));
        bufferevent_free(bev_in);
        bufferevent_free(bev_out);
        return;
    }

    // Setup callbacks and enable events
    bufferevent_setcb(bev_in, read_cb, NULL, event_cb, bev_out);
    bufferevent_setcb(bev_out, read_cb, NULL, event_cb, bev_in);
    bufferevent_enable(bev_in, EV_READ|EV_WRITE);
    bufferevent_enable(bev_out, EV_READ|EV_WRITE);

    current_bev = bev_in;
    debug(LOG_INFO, "Connected to remote server %s:%d", 
          get_common_config()->server_addr, trs->ps->remote_port);
}

static int setup_server_address(struct tcp_redir_service *trs, const char *server_addr) {
    if (is_valid_ip_address(server_addr)) {
        trs->server_addr.sin_addr.s_addr = inet_addr(server_addr);
    } else {
        struct hostent *host = gethostbyname(server_addr);
        if (!host || host->h_addrtype != AF_INET) {
            debug(LOG_ERR, "Invalid host or unsupported address type (only IPv4 supported)");
            return -1;
        }
        trs->server_addr.sin_addr.s_addr = *(unsigned long *)host->h_addr_list[0];
    }
    return 0;
}

static int initialize_listener(struct event_base *base, struct tcp_redir_service *trs) {
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(trs->ps->local_port),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };

    struct evconnlistener *listener = evconnlistener_new_bind(base, accept_cb, trs,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, 
        (struct sockaddr *)&sin, sizeof(sin));

    if (!listener) {
        debug(LOG_ERR, "Failed to create listener");
        return -1;
    }
    return 0;
}

/**
 * @brief Worker thread function for TCP redirection.
 * 
 * This function serves as the entry point for a worker thread that handles
 * TCP redirection operations. It processes the redirected TCP connections
 * according to the configuration specified in the argument.
 *
 * @param arg Pointer to thread-specific arguments
 * @return void* Returns NULL on completion
 */
static void *tcp_redir_worker(void *arg) {
    struct proxy_service *ps = (struct proxy_service *)arg;
    struct common_conf *c_conf = get_common_config();
    struct event_base *base;
    struct tcp_redir_service trs = {0};

    if (!ps || !c_conf) {
        debug(LOG_ERR, "Invalid arguments");
        return NULL;
    }

    if (!(base = event_base_new())) {
        debug(LOG_ERR, "Failed to create event base");
        return NULL;
    }

    // Initialize tcp_redir_service structure
    trs.base = base;
    trs.ps = ps;
    trs.server_addr.sin_family = AF_INET;
    trs.server_addr.sin_port = htons(ps->remote_port);

    if (setup_server_address(&trs, c_conf->server_addr) < 0) {
        event_base_free(base);
        return NULL;
    }

    if (initialize_listener(base, &trs) < 0) {
        event_base_free(base);
        return NULL;
    }

    event_base_dispatch(base);
    event_base_free(base);

    return NULL;
}

/**
 * @brief Starts the TCP redirection service for a given proxy service.
 * 
 * This function initiates the TCP redirection service, setting up the necessary
 * network configurations and handlers for the specified proxy service.
 * 
 * @param ps Pointer to the proxy service structure containing service configuration
 *           and connection details.
 * 
 * @return void
 * 
 * @note The proxy service structure must be properly initialized before calling
 *       this function.
 */
void start_tcp_redir_service(struct proxy_service *ps)
{
    pthread_t tid;
    int ret;

    if (!ps) {
        debug(LOG_ERR, "Invalid proxy service parameter");
        return;
    }

    ret = pthread_create(&tid, NULL, tcp_redir_worker, ps);
    if (ret != 0) {
        debug(LOG_ERR, "Failed to create tcp_redir worker thread: %s", strerror(ret));
        return;
    }

    ret = pthread_detach(tid);
    if (ret != 0) {
        debug(LOG_ERR, "Failed to detach tcp_redir worker thread: %s", strerror(ret));
        return;
    }

    debug(LOG_INFO, "TCP redirection service started successfully");
}