/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/** @file proxy_tcp.c
    @brief xfrp proxy tcp implemented
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/event.h>

#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"
#include "config.h"
#include "tcpmux.h"

#define	BUF_LEN	2*1024
#define SOCKS5_ADDRES_LEN 257
struct socks5_addr {
	u8 	type;
	u8 	addr[SOCKS5_ADDRES_LEN];
	u16 port;
};

static int
is_socks5(u8 *buf, int len)
{
	if (len < 3)
		return 0;
	if (buf[0] != 0x05)
		return 0;
	if (buf[1] != 0x01)
		return 0;
	if (buf[2] != 0x00)
		return 0;
	return 1;
}

static struct socks5_addr *addr  
parse_socks5_addr(u8 *buf, int len, int *offset)
{
	struct socks5_addr *addr = NULL;
	if (len < 10)
		return NULL;
	if (buf[3] == 0x01) { // ipv4
		if (len < 10)
			return NULL;
		addr = (struct socks5_addr *)malloc(sizeof(struct socks5_addr));
		assert(addr);
		memset(addr, 0, sizeof(struct socks5_addr));
		addr->type = 0x01;
		memcpy(addr->addr, buf + 4, 4);
		memcpy(addr->port, buf + 8, 2);
		*offset = 10;
	} else if (buf[3] == 0x03) { // domain
		if (len < 7 + buf[4])
			return NULL;
		addr = (struct socks5_addr *)malloc(sizeof(struct socks5_addr));
		assert(addr);
		memset(addr, 0, sizeof(struct socks5_addr));
		addr->type = 0x03;
		addr->addr_len = buf[4];
		memcpy(addr->addr, buf + 5, buf[4]);
		memcpy(addr->port, buf + 5 + buf[4], 2);
		*offset = 7 + buf[4];
	} else if (buf[3] == 0x04) { // ipv6
		if (len < 22)
			return NULL;
		addr = (struct socks5_addr *)malloc(sizeof(struct socks5_addr));
		assert(addr);
		memset(addr, 0, sizeof(struct socks5_addr));
		addr->type = 0x04;
		memcpy(addr->addr, buf + 4, 16);
		memcpy(addr->port, buf + 20, 2);
		*offset = 22;
	}
	return addr;
}

static struct bufferevent *
socks5_proxy_connect(struct proxy_client *client, struct socks5_addr *addr)
{
	struct bufferevent *bev = NULL;
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = addr->port;
	memcpy(&sin.sin_addr, addr->addr, 4);
	bev = bufferevent_socket_new(client->evbase, -1, BEV_OPT_CLOSE_ON_FREE);
	assert(bev);
	bufferevent_setcb(bev, tcp_proxy_s2c_cb, NULL, tcp_proxy_event_cb, client);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
	if (bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		bufferevent_free(bev);
		return NULL;
	} 
	return bev;
}

void
forward_socks5_data_2_target(struct proxy_client *client, struct ring_buffer *rb, int len)
{
	// if client's local_bev is not NULL, then we should forward rb's data to local_bev
	if (client->local_bev != NULL) {
		rx_ring_buffer_write(client->local_bev, rb, len);
		return;
	}

	// if client's local_bev is NULL, then we should connect to target
	if (is_socks5(rb->buf, len)) {
		int offset = 0;
		struct socks5_addr *addr = parse_socks5_addr(rb->buf, len, &offset);
		if (addr == NULL) {
			debug(LOG_ERR, "parse_socks5_addr failed");
			return;
		}
		client->local_bev = socks5_proxy_connect(client, addr);
		if (client->local_bev == NULL) {
			debug(LOG_ERR, "socks5_proxy_connect failed");
			return;
		}
		rx_ring_buffer_write(client->local_bev, rb, len - offset);
	} else {
		debug(LOG_ERR, "not socks5 protocol");
	}
}

// read data from local service
void tcp_proxy_c2s_cb(struct bufferevent *bev, void *ctx)
{
	struct common_conf  *c_conf = get_common_config();
	struct proxy_client *client = (struct proxy_client *)ctx;
	assert(client);
	struct bufferevent *partner = client->ctl_bev;
	assert(partner);
	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	assert(len > 0);
	if (!c_conf->tcp_mux) {
		struct evbuffer *dst = bufferevent_get_output(partner);
		evbuffer_add_buffer(dst, src);
		return;
	}

	uint8_t *buf = NULL;
	int offset = 0;
	if (is_socks5_proxy(client->ps)) {
		// add socks5 header
		len += 4;
		offset = 4;
	}
	buf = (uint8_t *)malloc(len);
	assert(buf != NULL);
	memset(buf, 0, len);
	if (offset > 0) {
		// add socks5 header
		buf[0] = 0x05;
		buf[1] = 0x00;
		buf[2] = 0x00;
		buf[3] = 0x01;
	}
	uint32_t nr = bufferevent_read(bev, buf+offset, len-offset);
	assert(nr == len);

	nr = tmux_stream_write(partner, buf, len, &client->stream);
	if (nr < len) {
		debug(LOG_DEBUG, "stream_id [%d] len is %d tmux_stream_write %d data, disable read", client->stream.id, len, nr);
		bufferevent_disable(bev, EV_READ);
	}
	free(buf);
}

// read data from frps
// when tcp mux enable this function will not be used
void tcp_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	assert(client);
	struct bufferevent *partner = client->local_proxy_bev;
	assert(partner);
	struct evbuffer *src, *dst;
	src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	assert(len > 0);
	dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src);
}
