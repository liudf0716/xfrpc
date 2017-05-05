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

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "debug.h"
#include "client.h"
#include "uthash.h"

// connect to server
static struct bufferevent *connect_server(const struct event_base *base, const char *name, const int port)
{
	struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	assert(bev);
	
	if (bufferevent_socket_connect_hostname(bev, NULL, AF_INET, name, port)<0) {
		bufferevent_free(bev);
		return NULL;
	}
	
	return bev;
}

// xfrp client connect to local server
void connect_local_server()
{
}

// create frp tunnel for service
static void start_frp_tunnel()
{
}

// first connect frp server
static void login_frp_server(const struct event_base *base, const char *frp_name, const int frp_port, const struct control_request *req)
{
	struct bufferevent *bev = connect_server(base, frp_name, frp_prt);
	if (!bev) {
		return;
	}
	
	bufferevent_setcb(bev, xfrp_read_msg_cb, NULL, xfrp_event_cb, NULL);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	
	char *msg = NULL;
	int len = control_request_marshal(req, &msg);
	assert(msg);
	bufferevent_write(bev, msg, len);
	free(msg);
}

void xkrp_client()
{
	
}

