
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_CONTROL_H
#define XFRPC_CONTROL_H

#include "msg.h"
#include "uthash.h"

#define MAX_RETRY_TIMES 100
#define RETRY_DELAY_SECONDS 2

/**
 * @brief Main control structure for FRP client
 */
struct control {
    struct event_base *connect_base;  /* Main event base */
    struct evdns_base *dnsbase;       /* DNS resolver base */
    struct bufferevent *connect_bev;  /* Main I/O event buffer */
    struct event *ticker_ping;        /* Heartbeat timer */
    struct event *tcp_mux_ping_event; /* TCP multiplexing ping event */
    uint32_t tcp_mux_ping_id;         /* TCP multiplexing ping ID */
    struct tmux_stream stream;        /* Multiplexing stream */
};

/* Control lifecycle functions */
void init_main_control(void);
void run_control(void);
struct control *get_main_control(void);
void close_main_control(void);

/* Server connection functions */
struct bufferevent *connect_server(struct event_base *base, const char *name,
                                   const int port);
struct bufferevent *connect_udp_server(struct event_base *base);
void connect_eventcb(struct bufferevent *bev, short events, void *ptr);

/* Server communication functions */
void start_login_frp_server(struct event_base *base);
void send_login_frp_server(struct bufferevent *bev);
void login(void);
void send_new_proxy(struct proxy_service *ps);

/* Message handling functions */
void send_msg_frp_server(struct bufferevent *bev, const enum msg_type type,
                         const char *msg, const size_t msg_len,
                         struct tmux_stream *stream);

void send_msg_frp_server(struct bufferevent *bev, const enum msg_type type,
                         const char *msg, const size_t msg_len,
                         struct tmux_stream *stream);

void send_enc_msg_frp_server(struct bufferevent *bev, const enum msg_type type,
                             const char *msg, const size_t msg_len,
                             struct tmux_stream *stream);

void control_process(struct proxy_client *client);

void send_new_proxy(struct proxy_service *ps);

struct bufferevent *connect_server(struct event_base *base, const char *name,
                                   const int port);

struct bufferevent *connect_udp_server(struct event_base *base);

#endif //XFRPC_CONTROL_H
