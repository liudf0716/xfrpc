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
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
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


#include "debug.h"
#include "client.h"
#include "uthash.h"
#include "control.h"
#include "config.h"
#include "const.h"
#include "uthash.h"
#include "zip.h"
#include "common.h"
#include "proxy.h"
#include "utils.h"
#include "tcpmux.h"

static struct proxy_client 	*all_pc = NULL;

static void
xfrp_worker_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		debug(LOG_DEBUG, "working connection closed!");
		bufferevent_free(bev);
	}
}

static void 
xfrp_proxy_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	struct proxy_client *client = ctx;
	assert(client);

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		debug(LOG_DEBUG, "xfrpc proxy close connect server [%s:%d] stream_id %d: %s", 
						client->ps->local_ip, client->ps->local_port, 
						client->stream_id, strerror(errno));
		if (tmux_stream_close(client->ctl_bev, &client->stream)) {
			bufferevent_free(bev);
			client->local_proxy_bev = NULL;
		}
	} else if (what & BEV_EVENT_CONNECTED) {
		debug(LOG_DEBUG, "what [%d] client [%d] connected : %s", what, client->stream_id, strerror(errno));
		if (client->data_tail_size > 0) {
			debug(LOG_DEBUG, "send client data ...");
			send_client_data_tail(client);		
		}
	}
}

int 
is_ftp_proxy(const struct proxy_service *ps)
{
	if (! ps || ! ps->proxy_type)
		return 0;

	if (0 == strcmp(ps->proxy_type, "ftp") && ps->remote_data_port > 0)
		return 1;

	return 0;
}

// create frp tunnel for service
void 
start_xfrp_tunnel(struct proxy_client *client)
{
	if (! client->ctl_bev) {
		debug(LOG_ERR, "proxy client control bev is invalid!");
		return;
	}

	struct event_base *base = client->base;
	struct common_conf *c_conf = get_common_config();
	struct proxy_service *ps = client->ps;

	if ( !base ) {
		debug(LOG_ERR, "service event base get failed");
		return;
	}

	if ( !ps ) {
		debug(LOG_ERR, "service tunnel started failed, no proxy service resource.");
		return;
	}

	if ( !ps->local_port ) {
		debug(LOG_ERR, "service tunnel started failed, proxy service resource unvalid.");
		return;
	}

	client->local_proxy_bev = connect_server(base, ps->local_ip, ps->local_port);
	if ( !client->local_proxy_bev ) {
		debug(LOG_ERR, "frpc tunnel connect local proxy port [%d] failed!", ps->local_port);
		del_proxy_client_by_stream_id(client->stream_id);
		return;
	}
	
	debug(LOG_DEBUG, "proxy server [%s:%d] <---> client [%s:%d]", 
		  c_conf->server_addr, 
		  ps->remote_port, 
		  ps->local_ip ? ps->local_ip:"127.0.0.1",
		  ps->local_port);

	bufferevent_data_cb proxy_s2c_recv, proxy_c2s_recv;
	if (is_ftp_proxy(client->ps)) {
		proxy_c2s_recv = ftp_proxy_c2s_cb;
		proxy_s2c_recv = ftp_proxy_s2c_cb;
	} else {
		proxy_c2s_recv = tcp_proxy_c2s_cb; // local service ---> xfrpc
		proxy_s2c_recv = tcp_proxy_s2c_cb; // frps ---> xfrpc
	}
	
	if (!c_conf->tcp_mux) {
		bufferevent_setcb(client->ctl_bev, 
						proxy_s2c_recv, 
						NULL, 
						xfrp_worker_event_cb, 
						client);
		bufferevent_enable(client->ctl_bev, EV_READ|EV_WRITE);
	}

	bufferevent_setcb(client->local_proxy_bev, 
						proxy_c2s_recv, 
						NULL, 
						xfrp_proxy_event_cb, 
						client);
						
	bufferevent_enable(client->local_proxy_bev, EV_READ|EV_WRITE);
}

int 
send_client_data_tail(struct proxy_client *client)
{
	int send_l = 0;
	if (client->data_tail && client->data_tail_size && client->local_proxy_bev) {
		send_l = bufferevent_write(client->local_proxy_bev, client->data_tail, client->data_tail_size);
		client->data_tail = NULL;
		client->data_tail_size = 0;
	}

	return send_l;
}

static void 
free_proxy_client(struct proxy_client *client)
{
	debug(LOG_DEBUG, "free client %d", client->stream_id);
	if (client->local_proxy_bev) bufferevent_free(client->local_proxy_bev);
	free(client);
}

static void 
del_proxy_client(struct proxy_client *client)
{
	if (!client || !all_pc ) {
		debug(LOG_INFO, "all_pc or client is NULL");
		return;
	}
	
	HASH_DEL(all_pc, client);
	
	free_proxy_client(client);
}

void
del_proxy_client_by_stream_id(uint32_t sid)
{
	del_stream(sid);

	struct proxy_client *pc = get_proxy_client(sid);
	del_proxy_client(pc);
}

struct proxy_client *
get_proxy_client(uint32_t sid)
{
	struct proxy_client *pc = NULL;
	HASH_FIND_INT(all_pc, &sid, pc);
	return pc;
}

struct proxy_client *
new_proxy_client()
{
	struct proxy_client *client = calloc(1, sizeof(struct proxy_client));
	assert(client);
	client->stream_id   = get_next_session_id();
	init_tmux_stream(&client->stream, client->stream_id, INIT);
	HASH_ADD_INT(all_pc, stream_id, client);
	
	return client;
}

void
clear_all_proxy_client()
{
	clear_stream();

	if (!all_pc) return;	

	struct proxy_client *client, *tmp;
	HASH_ITER(hh, all_pc, client, tmp) {
		HASH_DEL(all_pc, client);
		free_proxy_client(client);
	}
	all_pc = NULL;
}
