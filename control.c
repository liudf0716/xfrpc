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
#include "uthash.h"
#include "frame.h"


static struct control *main_ctl;

static void start_xfrp_client(struct event_base *base)
{
	struct proxy_client *all_pc = get_all_pc();
	struct proxy_client *pc = NULL, *tmp = NULL;
	
	debug(LOG_INFO, "Start xfrp client");
	
	HASH_ITER(hh, all_pc, pc, tmp) {
		pc->base = base;
		control_process(pc);
	}
}

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
	req->proxy_name = strdup(client->name);
	#define	STRDUP(v)	v?strdup(v):NULL
	switch((int)type) {
		case TypeLogin:
			req->use_encryption = client->bconf->use_encryption;
			req->use_gzip = client->bconf->use_gzip;
			req->pool_count = client->bconf->pool_count;
			req->privilege_mode = client->bconf->privilege_mode;
			req->proxy_type = STRDUP(client->bconf->type);
			req->host_header_rewrite = STRDUP(client->bconf->host_header_rewrite);
			req->http_username = STRDUP(client->bconf->http_username);
			req->http_password = STRDUP(client->bconf->http_password);
			req->subdomain = STRDUP(client->bconf->subdomain);
			if (req->privilege_mode) {
				req->remote_port = client->remote_port;
				req->custom_domains = STRDUP(client->custom_domains);
				req->locations = STRDUP(client->locations);
			}
			break;
		// case NewWorkConn:	
		// 	break;
		// case NoticeUserConn:
		// 	break;
		// case NewCtlConnRes:
		// 	break;
		// case HeartbeatReq:
		// 	break;
		// case HeartbeatRes:
		// 	break;
		// case NewWorkConnUdp:
		// 	break;
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

void send_msg_frp_server(enum msg_type type, const struct proxy_client *client, struct bufferevent *bev)
{
	char *msg = NULL;
	struct control_request *req = get_control_request(type, client); // get control request by client
	int len = control_request_marshal(req, &msg); // marshal control request to json string
	assert(msg);
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = client->ctl_bev;
	}
	bufferevent_write(bout, msg, len);
	bufferevent_write(bout, "\n", 1);
	debug(LOG_DEBUG, "Send msg to frp server [%s]", msg);
	free(msg);
	control_request_free(req); // free control request
}

void send_login_frp_server(struct bufferevent *bev)
{
	char *lg_msg = NULL;
	int len = login_request_marshal(&lg_msg); // marshal login request to json string
	assert(lg_msg);
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		return;
	}

	bufferevent_write(bout, lg_msg, len);
	bufferevent_write(bout, "\n", 1);
	debug(LOG_DEBUG, "Send msg to frp server [%s]", lg_msg);
	// free(lg_msg);
	// TODO CONTROL FREE
	// control_request_free(lg_msg); // free control request
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
	struct proxy_client *client = arg;
	
	send_msg_frp_server(TypeLogin, client, NULL);
	
	set_heartbeat_interval(client->ev_timeout);	
}

static void heartbeat_sender(struct proxy_client *client)
{
	client->ev_timeout = evtimer_new(client->base, hb_sender_cb, client);
	set_heartbeat_interval(client->ev_timeout);
}

// static void process_frp_msg(char *res, struct proxy_client *client)
// {
// 	struct control_response *c_res = control_response_unmarshal(res);
// 	if (c_res == NULL)
// 		return;
	
// 	switch(c_res->type) {
// 	// case HeartbeatRes:
// 	// 	break;
// 	case TypeLogin:
// 		// when user connect
// 		start_frp_tunnel(client);
// 		break;
// 	default:
// 		break;
// 	}
	
// 	control_response_free(c_res);
// }

// static void login_xfrp_read_msg_cb(struct bufferevent *bev, void *ctx)
// {
// 	struct evbuffer *input = bufferevent_get_input(bev);
// 	int len = evbuffer_get_length(input);
// 	if (len <= 0)
// 		return;
	
// 	char *buf = calloc(1, len+1);
// 	if (evbuffer_remove(input, buf, len) > 0) { 
// 		process_frp_msg(buf, ctx);
// 	}
// 	free(buf);
// }


static void login_xfrp_read_msg_cb2(struct bufferevent *bev, void *ctx)
{
	debug(LOG_ERR, "Proxy login: connect server OKKKKKKKK!@");
}


// static void login_xfrp_event_cb(struct bufferevent *bev, short what, void *ctx)
// {
// 	struct proxy_client *client = (struct proxy_client *)ctx;
// 	struct common_conf 	*c_conf = get_common_config();

// 	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
// 		if (client->ctl_bev != bev) {
// 			debug(LOG_ERR, "Error: should be equal");
// 			bufferevent_free(client->ctl_bev);
// 			client->ctl_bev = NULL;
// 		}
// 		debug(LOG_ERR, "Proxy [%s]: connect server [%s:%d] error", client->name, c_conf->server_addr, c_conf->server_port);
// 		bufferevent_free(bev);
// 		free_proxy_client(client);
// 	} else if (what & BEV_EVENT_CONNECTED) {
// 		debug(LOG_INFO, "Proxy [%s] connected: send msg to frp server", client->name);
// 		bufferevent_setcb(bev, login_xfrp_read_msg_cb, NULL, login_xfrp_event_cb, client);
// 		bufferevent_enable(bev, EV_READ|EV_WRITE);
		
// 		send_msg_frp_server(TypeLogin, client, NULL);
// 	}
// }


static void open_session(struct bufferevent *bev)
{
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		return;
	}

	main_ctl->session_id += 2;
	struct frame *f = new_frame(cmdSYN, main_ctl->session_id);
	assert(f);

	int headersize = get_header_size();
	size_t len = (1<<16) + headersize;
	char *buf = calloc(len, 1);

	buf[0] = f->ver;
	buf[1] = f->cmd;
	*(uint32_t *)(buf + 4) = f->sid;
	bufferevent_write(bout, buf, 2);
	// bufferevent_write(bout, "\n", 1);
	debug(LOG_DEBUG, "Send msg to frp server [%s]", buf);

	int i = 0;
	for(i; i<headersize; i++) {
		printf("%d\t", buf[i]);
	}

	printf("\n");
	// free(lg_msg);
	// TODO CONTROL FREE
	// control_request_free(lg_msg); // free control request
}


static void login_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	struct common_conf 	*c_conf = get_common_config();
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		debug(LOG_ERR, "Xfrp login: connect server [%s:%d] error", c_conf->server_addr, c_conf->server_port);
	} else if (what & BEV_EVENT_CONNECTED) {
		debug(LOG_INFO, "Xfrp connected!");
		bufferevent_setcb(bev, login_xfrp_read_msg_cb2, NULL, login_event_cb, NULL);
		bufferevent_enable(bev, EV_READ|EV_WRITE);
		
		send_login_frp_server(bev);
		//TODO : SESSION
		// send_msg_frp_server(NewCtlConn, client, NULL);
	}
}

// copy from login_event_cb
static void connect_event_cb (struct bufferevent *bev, short what, void *ctx)
{
	struct common_conf 	*c_conf = get_common_config();
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		debug(LOG_ERR, "Xfrp login: connect server [%s:%d] error", c_conf->server_addr, c_conf->server_port);
	} else if (what & BEV_EVENT_CONNECTED) {
		debug(LOG_INFO, "Xfrp connected: send msg to frp server");
		bufferevent_setcb(bev, login_xfrp_read_msg_cb2, NULL, login_event_cb, NULL);
		bufferevent_enable(bev, EV_READ|EV_WRITE);
		
		open_session(bev);
		// send_login_frp_server(bev);
		// send_msg_frp_server(NewCtlConn, client, NULL);
	}
}

// static void login_frp_server(struct proxy_client *client)
// {
// 	struct common_conf *c_conf = get_common_config();
// 	struct bufferevent *bev = connect_server(client->base, c_conf->server_addr, c_conf->server_port);
// 	if (!bev) {
// 		debug(LOG_DEBUG, "Connect server [%s:%d] failed", c_conf->server_addr, c_conf->server_port);
// 		return;
// 	}

// 	debug(LOG_INFO, "Proxy [%s]: connect server [%s:%d] ......", client->name, c_conf->server_addr, c_conf->server_port);

// 	client->ctl_bev = bev;
// 	bufferevent_enable(bev, EV_WRITE);
// 	bufferevent_setcb(bev, NULL, NULL, login_xfrp_event_cb, client);
// }



void start_login_frp_server(struct event_base *base)
{
	struct common_conf *c_conf = get_common_config();
	struct bufferevent *bev = connect_server(base, c_conf->server_addr, c_conf->server_port);
	if (!bev) {
		debug(LOG_DEBUG, "Connect server [%s:%d] failed", c_conf->server_addr, c_conf->server_port);
		return;
	}

	debug(LOG_INFO, "Xfrpc login: connect server [%s:%d] ......", c_conf->server_addr, c_conf->server_port);

	// client->ctl_bev = bev;
	bufferevent_enable(bev, EV_WRITE|EV_READ);
	bufferevent_setcb(bev, NULL, NULL, connect_event_cb, NULL);
}

void control_process(struct proxy_client *client)
{
	// login_frp_server(client);
	
	heartbeat_sender(client);	
}

static void start_base_connect() {
	struct common_conf *c_conf = get_common_config();
	main_ctl->connect_bev = connect_server(main_ctl->connect_base, 
												c_conf->server_addr, 
												c_conf->server_port);

	if ( ! main_ctl->connect_bev) {
		debug(LOG_DEBUG, "Connect server [%s:%d] failed", c_conf->server_addr, c_conf->server_port);
		return;
	}

	debug(LOG_INFO, "Xfrpc: connect server [%s:%d] ......", c_conf->server_addr, c_conf->server_port);

	// client->ctl_bev = bev;
	bufferevent_enable(main_ctl->connect_bev, EV_WRITE|EV_READ);
	bufferevent_setcb(main_ctl->connect_bev, NULL, NULL, connect_event_cb, NULL);
}

int init_main_control() {
	main_ctl = calloc(sizeof(struct control), 1);
	assert(main_ctl);
	struct event_base *base = NULL;
	base = event_base_new();
	if (!base) {
		debug(LOG_ERR, "event_base_new() error");
		return 1;
	}
	main_ctl->connect_base = base;
#ifdef CLIENT
	main_ctl->session_id = 1;
#elif SERVER
	main_ctl->session_id = 0;
#endif

	debug(LOG_DEBUG, "Connect session_id %d", main_ctl->session_id);
	return 0;
}

struct control *get_main_control() {
	return main_ctl;
}

void close_main_control() {
	assert(main_ctl);

	event_base_dispatch(main_ctl->connect_base);
	event_base_free(main_ctl->connect_base);
}

void run_control() {
	start_base_connect();
	// TODO :start_login_frp_server(main_ctl->connect_base);
}