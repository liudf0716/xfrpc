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

/** @file client.c
    @brief client surrogate for local service
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include <syslog.h>

#include <zlib.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include "debug.h"
#include "client.h"
#include "uthash.h"
#include "control.h"
#include "config.h"
#include "const.h"
#include "uthash.h"
#include "zip.h"
#include "msg.h"

#define MAX_OUTPUT (512*1024)

static void drained_writecb(struct bufferevent *bev, void *ctx);
static void xfrp_event_cb(struct bufferevent *bev, short what, void *ctx);

static void
xfrp_read_cb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (!partner) {
		evbuffer_drain(src, len);
		return;
	}
	dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src);

	if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
		/* We're giving the other side data faster than it can
		 * pass it on.  Stop reading here until we have drained the
		 * other side to MAX_OUTPUT/2 bytes. */
		bufferevent_setcb(partner, xfrp_read_cb, drained_writecb,
		    xfrp_event_cb, bev);
		bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
		    MAX_OUTPUT);
		bufferevent_disable(bev, EV_READ);
	}
}

static void
drained_writecb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;

	/* We were choking the other side until we drained our outbuf a bit.
	 * Now it seems drained. */
	bufferevent_setcb(bev, xfrp_read_cb, NULL, xfrp_event_cb, partner);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	if (partner)
		bufferevent_enable(partner, EV_READ);
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);

	if (evbuffer_get_length(b) == 0) {
		bufferevent_free(bev);
	}
}

static void
xfrp_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	struct bufferevent *partner = ctx;

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (partner) {
			/* Flush all pending data */
			xfrp_read_cb(bev, ctx);

			if (evbuffer_get_length(
				    bufferevent_get_output(partner))) {
				/* We still have to flush data from the other
				 * side, but when that's done, close the other
				 * side. */
				bufferevent_setcb(partner,
				    NULL, close_on_finished_writecb,
				    xfrp_event_cb, NULL);
				bufferevent_disable(partner, EV_READ);
			} else {
				/* We have nothing left to say to the other
				 * side; close it. */
				bufferevent_free(partner);
			}
		}
		bufferevent_free(bev);
	}
}

static void
xfrp_decrypt_cb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (len > 4) {
		dst = bufferevent_get_output(partner);
		evbuffer_drain(src, 4);
		evbuffer_add_buffer(dst, src);
	}
}

static void
xfrp_encrypt_cb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (len > 0) {
		dst = bufferevent_get_output(partner);
		unsigned int header = htonl(len);
		evbuffer_prepend(src, &header, sizeof(unsigned int));
		evbuffer_add_buffer(dst, src);	
	}
}

// create frp tunnel for service
void start_frp_tunnel(const struct proxy_client *client)
{
	struct event_base *base = client->base;
	struct common_conf *c_conf = get_common_config();
	
	struct bufferevent *b_svr = connect_server(base, c_conf->server_addr, c_conf->server_port);
	if (!b_svr) {
		return;
	}
	
	struct bufferevent *b_clt = connect_server(base, client->local_ip, client->local_port);
	if (!b_clt) {
		bufferevent_free(b_svr);
		return;
	}
	
	debug(LOG_DEBUG, "proxy server [%s:%d] <---> client [%s:%d]", 
		  c_conf->server_addr, c_conf->server_port, client->local_ip, client->local_port);
	
	bufferevent_setcb(b_svr, xfrp_decrypt_cb, NULL, xfrp_event_cb, b_clt);
	bufferevent_setcb(b_clt, xfrp_encrypt_cb, NULL, xfrp_event_cb, b_svr);
	
	bufferevent_enable(b_svr, EV_READ|EV_WRITE);
	bufferevent_enable(b_clt, EV_READ|EV_WRITE);
	
	// send_msg_frp_server(TypeNewProxy, client, b_svr);
}

void free_proxy_client(struct proxy_client *client)
{
	if (client->name) free(client->name);
	if (client->local_ip) free(client->local_ip);
	if (client->custom_domains) free(client->custom_domains);
	if (client->locations) free(client->locations);
	
	free_base_config(client->bconf);
	
	evtimer_del(client->ev_timeout);
}

void del_proxy_client(struct proxy_client *client)
{
	struct proxy_client *all_pc = get_all_pc();
	if (!client || !all_pc ) {
		debug(LOG_INFO, "Error: all_pc or client is NULL");
		return;
	}
	
	HASH_DEL(all_pc, client);
	
	free_proxy_client(client);
}
