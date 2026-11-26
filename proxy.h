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
void proxy_crypto_encode_evbuffer(struct proxy_client *client,
				  struct evbuffer *src, struct evbuffer *dst);
void proxy_crypto_decode_evbuffer(struct proxy_client *client,
				  struct evbuffer *src, struct evbuffer *dst);

// UDP proxy callbacks
void udp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void udp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);
void process_udp_rx_buf(struct proxy_client *client);
void process_udp_decomp_buf(struct proxy_client *client);
void init_udp_clean_timer(struct proxy_client *client);
void handle_udp_packet(struct udp_packet *udp_pkt, struct proxy_client *client);
void flush_udp_dns_pending(struct proxy_client *client);
void clear_udp_dns_pending(struct proxy_client *client);
void udp_deliver_tail_bytes(struct proxy_client *client, const uint8_t *data, size_t len);
int resolve_local_addr(const char *ip, struct sockaddr_in *addr);

// SOCKS5 protocol handler (reads directly from bev, no ring buffer)
void handle_socks5(struct proxy_client *client, struct bufferevent *bev, uint32_t len);
void socks5_proxy_s2c_cb(struct bufferevent *bev, void *ctx);

// XDPI service type handler (reads directly from bev, no ring buffer)
void handle_xdpi(struct proxy_client *client, struct bufferevent *bev, uint32_t len);
void xdpi_proxy_s2c_cb(struct bufferevent *bev, void *ctx);

#endif //XFRPC_PROXY_H
