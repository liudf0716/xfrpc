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

/** @file control.c
    @brief xfrp control protocol implemented
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

#include <json/json-c.h>

#include <syslog.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "debug.h"
#include "client.h"
#include "uthash.h"
#include "config.h"
#include "const.h"

static struct event timeout;

void send_msg_frp_server(const struct bufferevent *bev, msg_type type, const struct proxy_client *client)
{
	char *msg = NULL;
	struct control_request *req = get_control_request(type, client); // get control request by client
	int len = control_request_marshal(req, &msg); // marshal control request to json string
	assert(msg);
	bufferevent_write(bev, msg, len);
	free(msg);
	control_request_free(req); // free control request
}

// connect to server
struct bufferevent *connect_server(const struct event_base *base, const char *name, const int port)
{
	struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	assert(bev);
	
	if (bufferevent_socket_connect_hostname(bev, NULL, AF_INET, name, port)<0) {
		bufferevent_free(bev);
		return NULL;
	}
	
	return bev;
}

static void set_hearbeat_interval(struct event *timeout)
{
	struct timeval tv;
	struct common_conf *c_conf = get_common_conf();
	evutil_timerclear(&tv);
	tv.tv_sec = c_conf->heartbeat_interval;
	event_add(timeout, &tv);
}

static void hb_sender_cb(evutil_socket_t fd, short event, void *arg)
{
	struct bufferevent *bev = arg;
	
	send_msg_frp_server(bev, HeartbeatReq, NULL);
	
	set_heartbeat_interval(&timeout);	
}

static void heartbeat_sender(const struct event_base *base, struct bufferevent *bev)
{
	event_assign(&timeout, base, -1, EV_PERSIST, hb_sender_cb, (void*) bev);
	set_heartbeat_interval(&timeout);
}

static void xfrp_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
	}
}

static void process_frp_msg(char *res, struct proxy_client *client)
{
	struct control_response *c_res = control_respons_unmarshal(res);
	if (c_res == NULL)
		return;
	
	switch(c_res->type) {
	case HeartbeatRes:
		break;
	case NoticeUserConn:
		// when user connect
		start_frp_tunnel(client);
		break;
	default:
	}
	
	control_response_free(c_res);
}

static void xfrp_read_msg_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	int len = bufferevent_get_length(input);
	if (len <= 0)
		return;
	
	char *buf = calloc(1, len+1);
	if (evbuffer_remove(input, buf, len) > 0) { 
		process_frp_msg(buf, ctx);
	}
	free(buf);
}

static struct bufferevent *login_frp_server(struct proxy_client *client)
{
	struct common_conf *c_conf = get_common_conf();
	struct bufferevent *bev = connect_server(client->base, c_conf->server_addr, c_conf->server_port);
	
	bufferevent_setcb(bev, xfrp_read_msg_cb, NULL, xfrp_event_cb, client);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	
	send_msg_frp_server(bev, newCltConn, client);
	
	return bev;
}

void control_process(struct proxy_client *client)
{
	struct bufferevent *b_svr = login_frp_server(client);
	if (b_svr) {
		heartbeat_sender(base, b_svr);
	}
}
