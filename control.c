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

#include <json-c/json.h>

#include <syslog.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#include "debug.h"
#include "client.h"
#include "uthash.h"
#include "config.h"
#include "const.h"
#include "msg.h"
#include "control.h"
#include "uthash.h"
#include "frame.h"
#include "crypto.h"


static struct control *main_ctl;
static char *request_buf;

// static int start_proxy_service(struct proxy_client *pc)
// {
// 	debug(LOG_INFO, "start frps proxy service ...");
// 	char *proxy_msg = NULL;
// 	/////// COME HERE
// 	int len = login_request_marshal(&proxy_msg); //marshal login request
// 	if ( ! proxy_msg) {
// 		debug(LOG_ERR, "login_request_marshal failed");
// 		assert(proxy_msg);
// 	}

// 	send_msg_frp_server(NULL, TypeNewProxy, proxy_msg, len, main_ctl->session_id);
// }

static void start_xfrp_client_service()
{
	struct proxy_client *all_pc = get_all_pc();
	assert(all_pc);

	struct proxy_client *pc = NULL, *tmp = NULL;
	
	debug(LOG_INFO, "Start xfrp client");
	
	HASH_ITER(hh, all_pc, pc, tmp) {
		if(pc == NULL) {
			debug(LOG_ERR, "pc is null!");
			return;
		}
		pc->base = main_ctl->connect_base;
		// raw_new_proxy(pc);
		// send_new_proxy(pc);
	}
}

// TODO: need lock
static int 
request(struct bufferevent *bev, struct frame *f) {
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}

	if ( ! bout) {
		return 0;
	}

	/* debug showing */
	unsigned int i = 0;
	if (f->len > 20) {
		printf("[");
		for(i = 0; i<20; i++) {
			printf("%x ", f->data[i]);
		}
		printf("]\n");
		/* debug show over */
	}

	int headersize = get_header_size();
	size_t len = (1<<16) + headersize;
	printf("SET FRAME CMD:%d\n", f->cmd);

	memset(request_buf, 0, len);
	request_buf[VERI] = f->ver;
	request_buf[CMDI] = f->cmd;
	debug(LOG_DEBUG, "request data len = %u", f->len);
	*((ushort *)(request_buf + 2)) = f->len;
	*((uint32_t *)(request_buf + 4)) = f->sid;

	// 	insert data to request buffer
	if (f->data != NULL && f->len > 0) { //TODO: ENCODE when control
		memcpy(request_buf + DATAI, f->data, f->len);
	}

	size_t write_len = (size_t) (headersize + f->len);

	printf("******** Buffer write:\n");
	int j = 0;
	printf("[");
	for(j=0; j< write_len; j++) {
		printf("%d ", request_buf[j]);
	}
	printf("]\n");
	bufferevent_write(bout, request_buf, write_len);
	// bufferevent_write(bout, "\n", 1);
	debug(LOG_DEBUG, 
			"Send [%d] bits to frp server [%s]", 
			write_len, 
			request_buf);

	printf("[");
	for(i = 0; i<write_len; i++) {
		if (i == 0 || i == 1)
			printf("%d ", request_buf[i]);
		else if (i == 2)
			printf("%u ", *(ushort *)(request_buf + i));
		else if (i == 4)
			printf("%u ", request_buf[i]);
		else if (i>=8)
			printf("%d ", request_buf[i]);
	}
	printf("]\n");

	memset(request_buf, 0, len);
	return write_len;
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
		req->privilege_key = get_auth_key(client->bconf->privilege_token);
	} else {
		req->auth_key = get_auth_key(client->bconf->auth_token);
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


static void ping(struct bufferevent *bev)
{
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}

	if ( ! bout) 
		return;
	
	struct frame *f = new_frame(cmdNOP, 0);
	assert(f);

	request(bout, f);
}

// void send_m2sg_frp_server(enum msg_type type, const struct proxy_client *client, struct bufferevent *bev)
// {
// 	debug(LOG_DEBUG, "send ping ...");
// 	char *msg = NULL;
// 	struct control_request *req = get_control_request(type, client); // get control request by client
// 	int len = control_request_marshal(req, &msg); // marshal control request to json string
// 	assert(msg);
// 	struct bufferevent *bout = NULL;
// 	if (bev) {
// 		bout = bev;
// 	} else {
// 		bout = client->ctl_bev;
// 	}
// 	bufferevent_write(bout, msg, len);
// 	bufferevent_write(bout, "\n", 1);
// 	debug(LOG_DEBUG, "Send msg to frp server [%s]", msg);
// 	free(msg);
// 	control_request_free(req); // free control request
// }
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

static void set_ticker_ping_timer(struct event *timeout)
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
	
	ping(NULL);
	
	set_ticker_ping_timer(main_ctl->ticker_ping);	
}

static void heartbeat_sender(struct proxy_client *client)
{
	client->ev_timeout = evtimer_new(client->base, hb_sender_cb, client);
	set_ticker_ping_timer(client->ev_timeout);
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
static void login_xfrp_read_msg_cb2(struct bufferevent *bev, void *ctx)
{
	debug(LOG_ERR, "Proxy login: connect server OKKKKKKKK!@");
}

static int login_resp_check(struct login_resp *lr)
{
	struct login *cl = get_common_login_config();
	cl->logged = 1;
	if (cl->run_id)
		free(cl->run_id);

	cl->run_id = strdup(lr->run_id);
	return cl->logged;
}

static void recv_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	int len = evbuffer_get_length(input);
	if (len < 0)
		return;
	
	char *buf = calloc(1, len+1);
	if (evbuffer_remove(input, buf, len) > 0) { 
		debug(LOG_DEBUG, 
			"recv [%d] bits from frp server", 
			len);

		/* debug showing */
		unsigned int i = 0;
		printf("[");
		for(i = 0; i<len; i++) {
			printf("%x ", buf[i]);
		}
		printf("]\n");
		/* debug show over */
		struct frame *f = raw_frame(buf, len);
		if (f == NULL) {
			debug(LOG_ERR, "raw_frame faild!");
			return;
		}

		struct message *msg = len > get_header_size()? unpack(f->data, f->len):NULL;
		if (msg && msg->data_p) 
			debug(LOG_DEBUG, "RECV:%s\n", msg->data_p);
			
		switch(f->cmd) {
			case cmdNOP: 	//3 no options
				break;
			case cmdSYN: 	//0 create a new session
				break;
			case cmdFIN:	//1 close session
				break;
			case cmdPSH:	//2
				if (msg->data_p == NULL)
					break;
				struct login_resp *lr = login_resp_unmarshal(msg->data_p);
				printf("lr->version aass= %s\n", lr->version);
				// login_check();
			default:
				break;
		}
	} else {
		debug(LOG_DEBUG, "recved message but evbuffer_remove faild!");
	}

	// bufferevent_setcb(bev, login_xfrp_read_msg_cb2, NULL, NULL, NULL);
	// bufferevent_enable(bev, EV_READ|EV_WRITE);

	free(buf);
}

static void recv_login_resp_cb(struct bufferevent *bev, void *ctx)
{
	bufferevent_setcb(bev, recv_cb, NULL, NULL, NULL);
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	struct evbuffer *input = bufferevent_get_input(bev);
	int len = evbuffer_get_length(input);
	if (len < 0)
		return;
	
	char *buf = calloc(len+1, 1);
	assert(buf);

	if (evbuffer_remove(input, buf, len) > 0) { 
		debug(LOG_DEBUG, 
			"recv [%d] bits from frp server", 
			len);

		struct frame *f = raw_frame(buf, len);
		if (f == NULL) {
			debug(LOG_ERR, "raw_frame faild!");
			return;
		}

		struct message *msg = len > get_header_size()? unpack(f->data, f->len):NULL;

		if (! msg) {
			debug(LOG_ERR, "recved invalid loginresp message");
			goto END;
		}
		
		int is_logged = 0;
		switch(f->cmd) {
			case cmdPSH:	//2
				if (msg->data_p == NULL)
					break;
				struct login_resp *lr = login_resp_unmarshal(msg->data_p);
				is_logged = login_resp_check(lr);
				break;
			case cmdNOP: 	//3 no options
			case cmdSYN: 	//0 create a new session
			case cmdFIN:	//1 close session
			default:
				debug(LOG_ERR, "recved message but not login resp target.");
				break;
		}

		if (is_logged) {
			if (! is_encoder_inited()) {
				struct frp_encoder * e = init_main_encoder();
				if (!e)
					debug(LOG_ERR, "xfrp encoder init failed");

				sync_iv(e->iv);
			}
		}
		
	} else {
		debug(LOG_ERR, "recved login resp but evbuffer_remove faild!");
	}

END:
	free(buf);
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
	if ( ! bev) 
		return;

	main_ctl->session_id += 2;
	struct frame *f = new_frame(cmdSYN, main_ctl->session_id);
	assert(f);
	debug(LOG_DEBUG, "open session, send frame len=%d", f->len);
	request(bev, f);
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
		
		debug(LOG_DEBUG, "come in login_event_cb ... ");
		// send_login_frp_server(bev);
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
		// bufferevent_setcb(bev, recv_cb, NULL, login_event_cb, NULL);
		bufferevent_setcb(bev, recv_login_resp_cb, NULL, login_event_cb, NULL);
		bufferevent_enable(bev, EV_READ|EV_WRITE);
		
		open_session(bev);
		login();
	}
}

static void login_frp_server(struct proxy_client *client)
{
	struct common_conf *c_conf = get_common_config();
	struct bufferevent *bev = connect_server(client->base, c_conf->server_addr, c_conf->server_port);
	if (!bev) {
		debug(LOG_DEBUG, "Connect server [%s:%d] failed", c_conf->server_addr, c_conf->server_port);
		return;
	}

	debug(LOG_INFO, "Proxy [%s]: connect server [%s:%d] ......", client->name, c_conf->server_addr, c_conf->server_port);

	client->ctl_bev = bev;
	bufferevent_enable(bev, EV_WRITE);
	bufferevent_setcb(bev, NULL, NULL, NULL, client);
}

static void start_base_connect() 
{
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

static void keep_alive() 
{
	main_ctl->ticker_ping = evtimer_new(main_ctl->connect_base, 
									hb_sender_cb, 
									NULL);
	if ( ! main_ctl->ticker_ping) {
		debug(LOG_ERR, "Ping Ticker init failed!");
		return;
	}
	set_ticker_ping_timer(main_ctl->ticker_ping);
	
}

void send_msg_2_frp_server(enum msg_type type, const struct proxy_client *client, struct bufferevent *bev)
{
	debug(LOG_DEBUG, "send ping ...");
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

// TODO: NEED FREE IN FUNC
void sync_iv(unsigned char *iv)
{
	struct frame *f = new_frame(cmdPSH, main_ctl->session_id); // frame_type not truely matter, it will reset by set_frame_cmd
	assert(f);
	f->len = (ushort) get_encrypt_block_size();
	f->data = calloc(f->len, 1);
	memcpy(f->data, iv, f->len);

	struct bufferevent *bout = main_ctl->connect_bev;
	if ( ! bout) {
		return;
	}

	request(bout, f);
}

// TODO: NEED FREE frame
void sync_session_id(uint32_t sid)
{
	struct frame *f = new_frame(cmdNOP, sid);
	assert(f);

	size_t send_len = request(NULL, f);
	debug(LOG_DEBUG, "sync session id %d, len %ld", sid, send_len);
}

void 
send_msg_frp_server(struct bufferevent *bev, 
					const enum msg_type type, 
					const char *msg, 
					const size_t msg_len, 
					uint32_t sid)
{
	debug(LOG_DEBUG, "send message to frps ... [%s]", msg);
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}
	if ( ! bout) {
		return;
	}
	debug(LOG_DEBUG, "send message type is [%c]", type);

	struct message req_msg;
	char frame_type = 0;
	struct frame *f = NULL;
	req_msg.type = type;
	req_msg.data_len = msg_len;
	debug(LOG_DEBUG, "msg.data_len = %d", req_msg.data_len);
	if (msg) {
		req_msg.data_p = strdup(msg);
		//TODO: NEED FREE
	}

	char *puck_buf = NULL; //TODO: NEED FREE
	size_t pack_buf_len = pack(&req_msg, &puck_buf);
	if ( ! pack_buf_len || ! puck_buf) {
		debug(LOG_ERR, "login buffer pack failed!");
		return;
	}

	f = new_frame(frame_type, sid); // frame_type not truely matter, it will reset by set_frame_cmd
	assert(f);
	f->len = (ushort) pack_buf_len;
	f->data = puck_buf;

	switch (type)
	{
	case TypeLogin:
		frame_type = cmdPSH;
		
		break;
	case TypeNewProxy:	//will recv : {"proxy_name":"G_443","error":""}
		frame_type = cmdPSH;

		break;
	default:
		break;
	}

	set_frame_cmd(f, frame_type);
	/* debug showing */
	unsigned int i = 0;
	printf("[");
	for(i = 0; i<20; i++) {
		printf("%x ", puck_buf[i]);
	}
	printf("]\n");
	/* debug show over */

	/* debug showing */
	printf("[");
	for(i = 0; i<20; i++) {
		printf("%x ", f->data[i]);
	}
	printf("]\n");
	/* debug show over */

	printf("request length:%d\n", (ushort) f->len);
	request(bout, f);
}


// rule of frp login:
// 		frpc send msg:


void login()
{
	debug(LOG_INFO, "login frps ...");
	char *lg_msg = NULL;
	int len = login_request_marshal(&lg_msg); //marshal login request
	if ( ! lg_msg) {
		debug(LOG_ERR, "login_request_marshal failed");
		assert(lg_msg);
	}
	sync_session_id(3);
	send_msg_frp_server(NULL, TypeLogin, lg_msg, len, main_ctl->session_id);
}

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
	debug(LOG_DEBUG, "control proxy client: [%s]", client->name);
	// login_frp_server(client);

	char *new_proxy_msg = NULL;
	int len = new_proxy_request_marshal(client->n_proxy, &new_proxy_msg); //marshal login request
	if ( ! new_proxy_msg) {
		debug(LOG_ERR, "login_request_marshal failed");
		assert(new_proxy_msg);
	}

	send_msg_frp_server(NULL, TypeNewProxy, new_proxy_msg, len, main_ctl->session_id);
}

void send_new_proxy(struct proxy_client *client)
{
	debug(LOG_DEBUG, "control proxy client: [%s]", client->name);
	// login_frp_server(client);

	char *new_proxy_msg = NULL;
	int len = new_proxy_request_marshal(client->n_proxy, &new_proxy_msg); //marshal login request
	if ( ! new_proxy_msg) {
		debug(LOG_ERR, "login_request_marshal failed");
		assert(new_proxy_msg);
	}

	send_msg_frp_server(NULL, TypeNewProxy, new_proxy_msg, len, main_ctl->session_id);
}

int init_main_control() 
{
	main_ctl = calloc(sizeof(struct control), 1);
	assert(main_ctl);
	struct event_base *base = NULL;
	base = event_base_new();
	if (!base) {
		debug(LOG_ERR, "event_base_new() error");
		return 1;
	}
	main_ctl->connect_base = base;

	size_t len = (1<<16) + get_header_size();
	request_buf = calloc(len, 1);
	assert(request_buf);

#ifdef CLIENT
	main_ctl->session_id = 1;
#elif SERVER
	main_ctl->session_id = 0;
#endif

	debug(LOG_DEBUG, "Connect session_id %d", main_ctl->session_id);
	return 0;
}

struct control *get_main_control() 
{
	return main_ctl;
}

void close_main_control() 
{
	assert(main_ctl);

	event_base_dispatch(main_ctl->connect_base);
	event_base_free(main_ctl->connect_base);
}

void run_control() {
	start_base_connect();	//with login
	// start_xfrp_client_service();
	keep_alive();
	// TODO :start_login_frp_server(main_ctl->connect_base);
}