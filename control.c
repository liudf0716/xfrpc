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
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include <json-c/json.h>

#include <syslog.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#include <openssl/md5.h>

#include "debug.h"
#include "client.h"
#include "uthash.h"
#include "config.h"
#include "const.h"
#include "msg.h"
#include "control.h"

static struct event timeout;

static char *calc_md5(const char *data, int datalen)
{
	unsigned char digest[16] = {0};
	char *out = (char*)malloc(33);
	MD5_CTX md5;
	
	MD5_Init(&md5);
	MD5_Update(&md5, data, datalen);
	MD5_Final(digest, &md5);
	
	for (int n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 3, "%02x", (unsigned int)digest[n]);
    }

    return out;
}

static char *get_auth_key(const char *name, const char *token)
{
	char seed[128] = {0};
	snprintf(seed, 128, "%s%s%ld", name, token, time(NULL));
	
	return calc_md5(seed, strlen(seed));
}

static struct control_request *
get_control_request(enum msg_type type, const struct proxy_client *client)
{
	if (!client)
		return NULL;
	
	struct control_request *req = calloc(sizeof(struct control_request), 1);
	long ntime = time(NULL);
	req->type = type;
	switch(type) {
		case NewCtlConn:
			req->use_encryption = client->bconf->use_encryption;
			req->use_gzip = client->bconf->use_gzip;
			req->pool_count = client->bconf->pool_count;
			req->privilege_mode = client->bconf->privilege_mode;
			req->proxy_type = strdup(client->bconf->type);
			req->host_header_rewrite = strdup(client->bconf->host_header_rewrite);
			req->http_username = strdup(client->bconf->http_username);
			req->http_password = strdup(client->bconf->http_password);
			req->subdomain = strdup(client->bconf->subdomain);
			if (req->privilege_mode) {
				req->remote_port = client->remote_port;
				req->custom_domains = strdup(client->custom_domains);
				req->locations = strdup(client->locations);
			}
			break;
		case NewWorkConn:	
			break;
		case NoticeUserConn:
			break;
		case NewCtlConnRes:
			break;
		case HeartbeatReq:
			break;
		case HeartbeatRes:
			break;
		case NewWorkConnUdp:
			break;
	}
	
	req->privilege_mode = client->bconf->privilege_mode;
	req->timestamp = ntime;
	if (req->privilege_mode) {
		req->privilege_key = get_auth_key(client->name, client->bconf->privilege_token);
	} else {
		req->auth_key = get_auth_key(client->name, client->bconf->auth_token);
	}
	return req;
}

static void
control_request_free(struct control_request *req)
{
	if (!req)
		return;
	
	if (req->proxy_name) free(req->proxy_name);
	if (req->auth_key) free(req->auth_key);
	if (req->privilege_key) free(req->privilege_key);
	if (req->proxy_type) free(req->proxy_type);
	if (req->custom_domains) free(req->custom_domains);
	if (req->locations) free(req->locations);
	if (req->host_header_rewrite) free(req->host_header_rewrite);
	if (req->http_username) free(req->http_username);
	if (req->http_password) free(req->http_password);
	if (req->subdomain) free(req->subdomain);
	
	free(req);
}

void send_msg_frp_server(struct bufferevent *bev, enum msg_type type, const struct proxy_client *client)
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
struct bufferevent *connect_server(struct event_base *base, const char *name, const int port)
{
	struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	assert(bev);
	
	if (bufferevent_socket_connect_hostname(bev, NULL, AF_INET, name, port)<0) {
		bufferevent_free(bev);
		return NULL;
	}
	
	return bev;
}

static void set_heartbeat_interval(struct event *timeout)
{
	struct timeval tv;
	struct common_conf *c_conf = get_common_config();
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

static void heartbeat_sender(struct event_base *base, struct bufferevent *bev)
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
	struct control_response *c_res = control_response_unmarshal(res);
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
		break;
	}
	
	control_response_free(c_res);
}

static void xfrp_read_msg_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	int len = evbuffer_get_length(input);
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
	struct common_conf *c_conf = get_common_config();
	struct bufferevent *bev = connect_server(client->base, c_conf->server_addr, c_conf->server_port);
	
	bufferevent_setcb(bev, xfrp_read_msg_cb, NULL, xfrp_event_cb, client);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	
	send_msg_frp_server(bev, NewCtlConn, client);
	
	return bev;
}

void control_process(struct proxy_client *client)
{
	struct bufferevent *b_svr = login_frp_server(client);
	if (b_svr && client->base) {
		heartbeat_sender(client->base, b_svr);
	}
}
