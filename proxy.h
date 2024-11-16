/*
 * Copyright (c) 2016 Dengfeng Liu <liu_df@qq.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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
