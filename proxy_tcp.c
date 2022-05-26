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

#define	BUF_LEN	4096

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

	if (client->send_window == 0) {
		debug(LOG_DEBUG, "client %d recv len %d exceed send windows: %d", client->stream_id, len, client->send_window);
		bufferevent_disable(bev, EV_READ);
		return;
	} else {
		len = client->send_window>=len?len:client->send_window;
		client->send_window -= len;
	}

	tcp_mux_send_data(partner, client->stream_id, len);
	uint8_t buf[BUF_LEN];
	while(len > 0) {
		memset(buf, 0, BUF_LEN);
		int nread = bufferevent_read(bev, buf, len>BUF_LEN?BUF_LEN:len);
		assert(nread >= 0);
		bufferevent_write(partner, buf, nread);
		len -= nread;
	}
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
