
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

// FTP passive mode related structures
struct ftp_pasv {
	int     code;
	char    ftp_server_ip[IP_LEN];
	int     ftp_server_port;
};

// Generic proxy structure
struct proxy {
	struct bufferevent  *bev;
	char               *proxy_name;
	int                remote_data_port;    // Used in FTP proxy
};

// Proxy object management functions
struct proxy *new_proxy_obj(struct bufferevent *bev);
void free_proxy_obj(struct proxy *p);

// TCP proxy callbacks
void tcp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void tcp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);

// FTP proxy callbacks and helpers
void ftp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void ftp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);
void set_ftp_data_proxy_tunnel(const char *ftp_proxy_name, 
							  struct ftp_pasv *local_fp, 
							  struct ftp_pasv *remote_fp);

// UDP proxy callbacks
void udp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void udp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);
void handle_udp_packet(struct udp_packet *udp_pkt, struct proxy_client *client);

// SOCKS protocol handlers
uint32_t handle_socks5(struct proxy_client *client, struct ring_buffer *rb, int len);
uint32_t handle_ss5(struct proxy_client *client, struct ring_buffer *rb, int len);

#endif //XFRPC_PROXY_H
