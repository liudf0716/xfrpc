// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_PROXY_H
#define XFRPC_PROXY_H

#include <stdint.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include "client.h"
#include "common.h"
#include "tcpmux.h"
#include "msg.h"

#define IP_LEN 16

// Generic proxy structure
struct proxy {
	struct bufferevent  *bev;
	char               *proxy_name;
};

// Proxy object management functions
struct proxy *new_proxy_obj(struct bufferevent *bev);
void free_proxy_obj(struct proxy *p);

// TCP proxy callbacks
void tcp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void tcp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);

// UDP proxy callbacks
void udp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void udp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);
void handle_udp_packet(struct udp_packet *udp_pkt, struct proxy_client *client);

// SOCKS5 protocol handler (reads directly from bev, no ring buffer)
void handle_socks5(struct proxy_client *client, struct bufferevent *bev, uint32_t len);
void socks5_proxy_s2c_cb(struct bufferevent *bev, void *ctx);

// XDPI service type handler (reads directly from bev, no ring buffer)
void handle_xdpi(struct proxy_client *client, struct bufferevent *bev, uint32_t len);
void xdpi_proxy_s2c_cb(struct bufferevent *bev, void *ctx);

#endif //XFRPC_PROXY_H
