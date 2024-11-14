/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
\********************************************************************/

/**
 * @file control.h
 * @brief Main control interface for FRP (Fast Reverse Proxy) client
 * @author Dengfeng Liu <liu_df@qq.com>
 * @copyright Copyright (C) 2016 Dengfeng Liu
 *
 * This file contains the core control structures and functions
 * for managing FRP client connections and communications.
 */

#ifndef CONTROL_H_
#define CONTROL_H_

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

#endif //_CONTROL_H_
