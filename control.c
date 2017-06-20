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
#include <pthread.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/dns.h>
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
#include "utils.h"
#include "session.h"
#include "common.h"

static struct control *main_ctl;
static char *request_buf;
static int clients_conn_signel = 0;

static void sync_new_work_connection(struct bufferevent *bev);
static void recv_cb(struct bufferevent *bev, void *ctx);

static int is_client_connected()
{
	return clients_conn_signel;
}

static int client_connected(int is_connected)
{
	if (is_connected)
		clients_conn_signel = 1;
	else
		clients_conn_signel = 0;

	return clients_conn_signel;
}

static int set_client_work_start(struct proxy_client *client, int is_start_work)
{
	if (is_start_work)
		client->work_started = 1;
	else
		client->work_started = 0;

	return client->work_started;
}

static int is_client_work_started(struct proxy_client *client) {
	return client->work_started;
}

static void client_start_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	struct proxy_client *client = ctx;
	assert(client);
	struct common_conf 	*c_conf = get_common_config();

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (client->ctl_bev != bev) {
			debug(LOG_ERR, "Error: should be equal");
			bufferevent_free(client->ctl_bev);
			client->ctl_bev = NULL;
		}
		debug(LOG_ERR, "Proxy [%s]: connect server [%s:%d] error", client->name, c_conf->server_addr, c_conf->server_port);
		bufferevent_free(bev);
		free_proxy_client(client);
	} else if (what & BEV_EVENT_CONNECTED) {
		bufferevent_setcb(bev, recv_cb, NULL, client_start_event_cb, client);
		bufferevent_enable(bev, EV_READ|EV_WRITE);
		sync_new_work_connection(bev);
		debug(LOG_INFO, "new proxy connected");
	}
}

static void new_client_connect()
{
	struct proxy_client *client = calloc(1, sizeof(struct proxy_client)); //NEED FREE
	assert(client);
	struct common_conf *c_conf = get_common_config();
	assert(c_conf);
	client->base = main_ctl->connect_base;;
	struct bufferevent *bev = connect_server(client->base, c_conf->server_addr, c_conf->server_port);
	if (!bev) {
		debug(LOG_DEBUG, "Connect server [%s:%d] failed", c_conf->server_addr, c_conf->server_port);
		return;
	}

	debug(LOG_INFO, "Proxy [%s]: connect server [%s:%d] ......", client->name, c_conf->server_addr, c_conf->server_port);

	client->ctl_bev = bev;
	bufferevent_enable(bev, EV_WRITE);
	bufferevent_setcb(bev, NULL, NULL, client_start_event_cb, client);
}

static void start_proxy_services()
{
	struct proxy_service *all_ps = get_all_proxy_services();
	assert(all_ps);

	struct proxy_service *ps = NULL, *tmp = NULL;
	
	debug(LOG_INFO, "Start xfrp proxy services ...");
	
	HASH_ITER(hh, all_ps, ps, tmp) {
		if(ps == NULL) {
			debug(LOG_ERR, "pc is null!");
			return;
		}
		send_new_proxy(ps);
	}
}

#ifdef USEENCRYPTION
static void init_msg_writer()
{
	if (! is_encoder_inited()) {
		struct frp_coder * e = init_main_encoder();
		if (e)
			sync_iv(e->iv);
	}
}

static void init_msg_reader(unsigned char *iv)
{
	if (! is_decoder_inited()) {
		struct frp_coder *d = init_main_decoder(iv);
		if (!d) {
			debug(LOG_DEBUG, "reader init faild!");
		}
	}
}
#endif // USEENCRYPTION

static size_t request(struct bufferevent *bev, struct frame *f) 
{
	size_t write_len = 0;
	struct bufferevent *bout = NULL;

	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}

	if ( ! bout) {
		goto REQ_END;
	}

// #define DEV_DEBUG 1
#ifdef DEV_DEBUG
	/* debug showing */
	debug(LOG_DEBUG, "send request byte:");
	unsigned int i = 0;
	if (f->len) {
		printf("[");
		for(i = 0; i<f->len; i++) {
			printf("%u ", f->data[i]);
		}
		printf("]\n");
	}
#endif // DEV_DEBUG

	struct common_conf *c = get_common_config();
	if ( ! c)
		goto REQ_END;

	int headersize = get_header_size();
	size_t len = (1<<16) + headersize;

	memset(request_buf, 0, len);
	if (c->tcp_mux) {
		request_buf[VERI] = f->ver;
		request_buf[CMDI] = f->cmd;
		*((ushort *)(request_buf + 2)) = f->len;
		*((uint32_t *)(request_buf + 4)) = f->sid;

		// 	insert data to request buffer
		if (f->data != NULL && f->len > 0) { //TODO: ENCODE when control
			memcpy(request_buf + DATAI, f->data, f->len);
		}
		write_len = (size_t) (headersize + f->len);

	} else {
		memcpy(request_buf, f->data, f->len);
		write_len = (size_t)f->len;
	}

	if ( 0 == write_len)
		goto REQ_END;;

	bufferevent_write(bout, request_buf, write_len);
	memset(request_buf, 0, len);

REQ_END:
	return write_len;
}

void control_request_free(struct control_request *req)
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

static void base_control_ping(struct bufferevent *bev) {
	if ( ! is_client_connected())
		return;

	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}

	if ( ! bout) {
		debug(LOG_ERR, "bufferevent is not legal!");
		return;
	}

	struct frame *f = new_frame(cmdNOP, 0); //ping sid is 0
	assert(f);

	request(bout, f);
}

static void ping(struct bufferevent *bev)
{
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}

	if ( ! bout) {
		debug(LOG_ERR, "bufferevent is not legal!");
		return;
	}
	
	/* tcp-mux using frame */
	// struct frame *f = new_frame(cmdNOP, 0); //ping sid is 0
	// assert(f);
	// request(bout, f);

	uint32_t sid = get_main_control()->session_id;

	char *ping_msg = "{}";
	send_msg_frp_server(bev, TypePing, ping_msg, strlen(ping_msg), sid);
}

static void pong(struct bufferevent *bev, struct frame *f)
{
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}

	if ( ! bout) {
		debug(LOG_ERR, "bufferevent is not legal!");
		return;
	}

	uint32_t sid = 0;
	if (!f || f->sid == 0)
		sid = get_main_control()->session_id;
	else
		sid = f->sid;

	char *pong_msg = "{}";

	send_msg_frp_server(bev, TypePong, pong_msg, strlen(pong_msg), sid);
}

static void sync_new_work_connection(struct bufferevent *bev)
{
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}

	if ( ! bout) {
		debug(LOG_ERR, "bufferevent is not legal!");
		return;
	}
	
	/* send new work session regist request to frps*/
	uint32_t sid = 5;
	struct frame *f = new_frame(cmdSYN, sid);
	assert(f);

	struct work_conn *work_c = new_work_conn();
	assert(work_c);
	work_c->run_id = get_run_id();
	if (! work_c->run_id) {
		debug(LOG_ERR, "login is not init the run ID!");
		return;
	}
	char *new_work_conn_request_message = NULL;
	int nret = new_work_conn_marshal(work_c, &new_work_conn_request_message);
	if (0 == nret) {
		debug(LOG_ERR, "new work connection request run_id marshal failed!");
		return;
	}
	debug(LOG_DEBUG, "marshal new work connection:%s", new_work_conn_request_message);

	send_msg_frp_server(bev, TypeNewWorkConn, new_work_conn_request_message, nret, f->sid);
	request(bout, f);

	free(f);
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
	base_control_ping(NULL);
	if (is_client_connected())
		ping(NULL);

	set_ticker_ping_timer(main_ctl->ticker_ping);	
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

static void raw_message(struct message *msg, struct bufferevent *bev, struct proxy_client *client)
{
	if (client) {
		if (client->work_started) {
			debug(LOG_DEBUG, "raw client [%s] control message.", client->name);
		}
	}

	struct start_work_conn_resp *sr = NULL; //used in TypeStartWorkConn
	switch(msg->type) {
		case TypeLoginResp:
			if (msg->data_p == NULL)
				break;

			struct login_resp *lr = login_resp_unmarshal(msg->data_p);
			if (lr == NULL) {
				debug(LOG_ERR, "login response buffer init faild!");
				return;
			}

			debug(LOG_INFO, "xfrp login succeed!");
			login_resp_check(lr);

#ifdef USEENCRYPTION
			int is_logged = login_resp_check(lr);
			if (is_logged) {
				init_msg_writer();
				// sync_new_work_connection(NULL);
			}
#endif // USEENCRYPTION

			free(lr);
			break;
		case TypeReqWorkConn:
			if (! is_client_connected()) {
				debug(LOG_DEBUG, "recv the client work connect start request ...");
				start_proxy_services();
				client_connected(1);
				ping(bev);
			} else {
				debug(LOG_DEBUG, "clients have been connected.");
			}

			new_client_connect();
			break;

		case TypeNewProxyResp:
			break;
			
		case TypeStartWorkConn:
			sr = start_work_conn_resp_unmarshal(msg->data_p); 
			if (! sr) {
				debug(LOG_ERR, "TypeStartWorkConn unmarshal failed, it should never be happend!");
				break;
			}

			struct proxy_service *ps = get_proxy_service(sr->proxy_name);
			if (! ps) {
				debug(LOG_ERR, "TypeStartWorkConn requested proxy service [%s] not found, it should nerver be happend!", sr->proxy_name);
				break;
			}

			client->ps = ps;
			client->name = ps->proxy_name;
			debug(LOG_INFO, "proxy service [%s] start work connection.", sr->proxy_name);
			debug(LOG_DEBUG, "proxy service resource: [%s] [%s:%d]", ps->proxy_name, ps->local_ip, ps->local_port);

			start_frp_tunnel(client);
			set_client_work_start(client, 1);
			break;
		case TypePong:
			pong(bev, NULL);
			break;
		default:
			break;
	}
}

static size_t data_handler(unsigned char *buf, ushort len, struct proxy_client *client)
{
	struct bufferevent *bev = NULL;
	if (client) {
		debug(LOG_DEBUG, "client [name:%s] recved data", client->name);
		bev = client->ctl_bev;
	}
	unsigned char *ret_buf = NULL;
	struct frame *f = NULL;
	/* debug showing */
	unsigned int i = 0;
	debug(LOG_DEBUG, "RECV from frps:");
	printf("[");
	for(i = 0; i<len; i++) {
		printf("%d ", (unsigned char)buf[i]);
	}
	printf("]\n");
	/* debug show over */

	int min_buf_len = 0;
	if (get_common_config()->tcp_mux) {
		f = raw_frame(buf, len);
		min_buf_len = get_header_size();
	} else {
		f = raw_frame_only_msg(buf, len);
		set_frame_cmd(f, cmdPSH);
	}

	if (f == NULL) {
		debug(LOG_ERR, "raw_frame faild!");
		goto DATA_H_END;
	}

	debug(LOG_DEBUG, 
		"recv [%d] bits from frp server, frame: ver[%d], cmd[%d], len[%u], sid[%d]", 
		len, f->ver, f->cmd, f->len, f->sid);

#ifdef USEENCRYPTION
	if (! is_decoder_inited() && f->len == get_block_size()) {
		init_msg_reader((unsigned char *)f->data);
		debug(LOG_DEBUG, "first recv stream message, init decoder iv succeed!");
		goto DATA_H_END;
	}
#endif //USEENCRYPTION

	if (len <= min_buf_len) {
		if (f->cmd == 3) {
			base_control_ping(bev);
		}

		goto DATA_H_END;
	}

#ifdef ENCRYPTO
	//fuck debug
	size_t ret_len3 = encrypt_data(f->data, (size_t)f->len, get_main_encoder(), &ret_buf);
	if (ret_len3 <= 0) {
		debug(LOG_ERR, "message recved decrypt result is 0 bit");
		goto DATA_H_END;
	}

	debug(LOG_DEBUG, "message after test1:");
	for(i=0; i<ret_len3; i++) {
		printf("%u ", (unsigned char)ret_buf[i]);
	}

	printf("\n");

	size_t ret_len2 = decrypt_data(f->data, (size_t)f->len, get_main_encoder(), &ret_buf);
	debug(LOG_DEBUG, "message after test2:");
	if (ret_len2 <= 0) {
		debug(LOG_ERR, "message recved decrypt result is 0 bit");
		goto DATA_H_END;
	}

	for(i=0; i<ret_len2; i++) {
		printf("%u ", (unsigned char)ret_buf[i]);
	}
	printf("\n");

	size_t ret_len1 = encrypt_data(f->data, (size_t)f->len, get_main_decoder(), &ret_buf);
	if (ret_len1 <= 0) {
		debug(LOG_ERR, "message recved decrypt result is 0 bit");
		goto DATA_H_END;
	}

	debug(LOG_DEBUG, "message after test3:");
	for(i=0; i<f->len; i++) {
		printf("%u ", (unsigned char)ret_buf[i]);
	}
	printf("\n encrypto test end \n");

	struct frp_coder *d = get_main_decoder();
	if (! d) {
		debug(LOG_ERR, "decoder (message reader) is not inited!");
		goto DATA_H_END;
	}
	size_t ret_len = decrypt_data(f->data, (size_t)f->len, d, &ret_buf);
	if (ret_len <= 0) {
		debug(LOG_ERR, "message recved decrypt result is 0 bit");
		goto DATA_H_END;
	}

	debug(LOG_DEBUG, "message after decode:");
	for(i=0; i<f->len; i++) {
		printf("%u ", (unsigned char)ret_buf[i]);
	}
	printf("\n\n");
#endif //ENCRYPTO

	if (! ret_buf) 
		ret_buf = f->data; //test: no crypto

	struct message *msg = NULL;
	switch(f->cmd) {
		case cmdNOP: 	//3 no options
			break;
		case cmdSYN: 	//0 create a new session
			break;
		case cmdFIN:	//1 close session
			break;
		case cmdPSH:	//2
			msg = unpack(ret_buf, f->len);
			if (msg && msg->data_p) {
				debug(LOG_DEBUG, "RECV:%s\n", msg->data_p);
				debug(LOG_DEBUG, "recv <---- %s" ,msg->data_p);
			} else {
				debug(LOG_ERR, "message received format invalid");
				goto DATA_H_END;
			}

			if (msg->data_p == NULL)
				goto DATA_H_END;

			raw_message(msg, bev, client);
			break;
		default:
			break;
	}

	SAFE_FREE(msg);

DATA_H_END:
	SAFE_FREE(f);

	return len;
}

// ctx: if recv_cb was called by common control, ctx == NULL
//		else ctx == client struct
static unsigned char *multy_recv_buffer_raw(unsigned char *buf, size_t buf_len, size_t *ret_len, void *ctx)
{
	unsigned char *unraw_buf_p = NULL;
	unsigned char *raw_buf = NULL;
	size_t split_lv = sizeof(msg_size_t);		// latest buffer split level
	size_t split_len = 0;
	size_t raw_static_size = 1 + sizeof(msg_size_t); //type 1 + bigend 8
	int splited = 0; 			// signal argument, ==1 after buffer split

	*ret_len = 0;

	if (ctx) {
		struct proxy_client *client = (struct proxy_client *)ctx;
		if (is_client_work_started(client)) {
			debug(LOG_DEBUG, "client [%s] send all work data to proxy tunnel.", client->name);
			return NULL;
		}
	}

	for(;;) {
		if (buf_len > split_lv) {
			if (! is_logged()) {
				if (buf[0] == 49) {
					debug(LOG_DEBUG, "mulity raw login-response...");

					msg_size_t  data_len_bigend;
					data_len_bigend = *(msg_size_t *)(buf + MSG_LEN_I);
					msg_size_t data_len = msg_ntoh(data_len_bigend);
					debug(LOG_DEBUG, "raw data len = %u", data_len);

					split_len = raw_static_size + data_len;
					splited = 1;
					break;
				}
			}

#ifdef USEENCRYPTION
			if (! is_decoder_inited()) {
				raw_static_size = get_block_size();
				if (buf_len < raw_static_size) {
					break;
				}

				debug(LOG_DEBUG, "mulity raw decoder IV...");
				split_len = raw_static_size;
				splited = 1;
				break;
			}
#endif // USEENCRYPTION

			if (! splited) { //ordinary message split
				char msg_type = buf[0];
				int type_valid = msg_type_valid_check(msg_type);
				if (type_valid) {
					debug(LOG_DEBUG, "buffer raw type [%c]", msg_type);
					msg_size_t  data_len_bigend;
					data_len_bigend = *(msg_size_t *)(buf + MSG_LEN_I);
					msg_size_t data_len = msg_ntoh(data_len_bigend);

					split_len = raw_static_size + data_len;
					splited = 1;
				} else {
					debug(LOG_ERR, "buffer type [%c] raw failed!", msg_type);
				}
				break;
			}
		}

		break;
	}

	if (! splited) {
		data_handler(buf, buf_len, ctx);
		*ret_len = 0;
		return NULL;

	} else if (split_len){
		raw_buf =calloc(1, split_len);
		assert(raw_buf);
		memcpy(raw_buf, buf, split_len);
	}
	
	if (split_len != 0 && raw_buf != NULL){
		data_handler(raw_buf, split_len, ctx);
		free(raw_buf);
		*ret_len = buf_len - split_len;
		if (split_len < buf_len) {
			unraw_buf_p = buf+ split_len;
		}
	}

	return unraw_buf_p;
}

// ctx: if recv_cb was called by common control, ctx == NULL
//		else ctx == client struct
static void recv_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	int len = evbuffer_get_length(input);
	if (len < 0) {
		return;
	}

	unsigned char *buf = calloc(1, len);
	assert(buf);

	size_t read_n = 0;
	size_t ret_len = 0;
	read_n = evbuffer_remove(input, buf, len);

	struct proxy_client *client = (struct proxy_client *)ctx;
	if (read_n) {
		unsigned char *raw_buf_p = buf;
		for( ; raw_buf_p && read_n ; ) {

// #define CONN_DEBUG 1
#ifdef CONN_DEBUG
			unsigned int i = 0;
			char *dbg_buf = calloc(1, read_n * 4 + 1);
			assert(dbg_buf);
			for(i = 0; i<read_n && ((2 * i) < (read_n * 2 + 1)); i++) {
				snprintf(dbg_buf + 4*i, 5, "%3u ", (unsigned char)raw_buf_p[i]);
			}
			debug(LOG_DEBUG, "[%s]: RECV ctl byte:%s", client ? "client":"control", dbg_buf);
			free(dbg_buf);
#endif //CONN_DEBUG

			raw_buf_p = multy_recv_buffer_raw(raw_buf_p, read_n, &ret_len, client);
			read_n = ret_len;

			if (ctx && 
				is_client_work_started(client) && 
				raw_buf_p && 
				ret_len) {
				debug(LOG_WARNING, "warning: data recved from frps is not split clear!");
				unsigned char *dtail = calloc(1, read_n);
				assert(dtail);
				memcpy(dtail, raw_buf_p, read_n);
				client->data_tail = dtail;
				client->data_tail_size = ret_len;
				send_client_data_tail(client);
				free(dtail);
				client->data_tail = NULL;
				client->data_tail_size = 0;
			}
		}
	} else {
		debug(LOG_DEBUG, "recved message but evbuffer_remove faild!");
	}
	free(buf);

	return;
}

static void open_connection_session(struct bufferevent *bev)
{
	struct frame *f = new_frame(cmdSYN, main_ctl->session_id);
	assert(f);
	debug(LOG_DEBUG, "open session ID:%d", main_ctl->session_id);
	request(bev, f);
}


static void connect_event_cb (struct bufferevent *bev, short what, void *ctx)
{
	struct common_conf 	*c_conf = get_common_config();
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		debug(LOG_ERR, "Xfrp login: connect server [%s:%d] error", c_conf->server_addr, c_conf->server_port);
	} else if (what & BEV_EVENT_CONNECTED) {
		debug(LOG_INFO, "Xfrp connected: send msg to frp server");

		// recv frpc login-response message before recv othfer fprs messages, 
		bufferevent_setcb(bev, recv_cb, NULL, connect_event_cb, NULL);
		bufferevent_enable(bev, EV_READ|EV_WRITE|EV_PERSIST);
		bufferevent_setwatermark(bev, EV_READ, 0, 0);
		
		open_connection_session(bev);
		login();
	}
}

static void keep_control_alive() 
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

void start_base_connect()
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

	bufferevent_enable(main_ctl->connect_bev, EV_WRITE|EV_READ);
	bufferevent_setcb(main_ctl->connect_bev, NULL, NULL, connect_event_cb, NULL);
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

void send_msg_frp_server(struct bufferevent *bev, 
					const enum msg_type type, 
					const char *msg, 
					const size_t msg_len, 
					uint32_t sid)
{
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}

	if ( ! bout) {
		return;
	}
	debug(LOG_DEBUG, "send message to frps ... [type: %c %s]", type, msg);

	struct message req_msg;
	req_msg.data_p = NULL;
	req_msg.type = type;
	req_msg.data_len = msg_len;

	if (msg) {
		req_msg.data_p = strdup(msg);
	}

	unsigned char *puck_buf = NULL; //TODO: NEED FREE
	size_t pack_buf_len = pack(&req_msg, &puck_buf);
	if ( ! pack_buf_len || ! puck_buf) {
		debug(LOG_ERR, "login buffer pack failed!");
		return;
	}
	
// #define SEND_MSG_DEBUG 1
#ifdef SEND_MSG_DEBUG
	debug(LOG_DEBUG, "**puck result:");
	size_t j = 0;
	for(j=0; j<pack_buf_len; j++) {
		printf("%d ", (unsigned char)puck_buf[j]);
	}
	printf("\n\n");
#endif	// SEND_MSG_DEBUG

	char frame_type = 0;
	struct frame *f = NULL;
	f = new_frame(frame_type, sid); // frame_type not truely matter, it will reset by set_frame_cmd
	assert(f);

#ifdef ENCRYPTO
	debug(LOG_DEBUG, "start encode message ...");
	unsigned char *encode_ret;
	unsigned char *encode_ret_test;
	unsigned char *decode_ret_test;
	struct frp_coder *encoder = get_main_encoder();

	if (encoder) {
		size_t encode_ret_len = encrypt_data(puck_buf, pack_buf_len, encoder, &encode_ret);
		debug(LOG_DEBUG, "encode len:[%lu]", encode_ret_len);

		if (encode_ret_len > 0) {
			f->data = encode_ret;
			set_frame_len(f, (ushort) encode_ret_len);
		}

		set_frame_len(f, (ushort) pack_buf_len);
	}

#endif //ENCRYPTO
	if (! f->data) {
		set_frame_len(f, (ushort) pack_buf_len);
		f->data = puck_buf;
	}
	
	switch (type)
	{
	case TypeLogin:
	case TypePong:
	case TypePing:
	case TypeNewProxy:
		frame_type = cmdPSH;
		break;

	default:
		break;
	}

	set_frame_cmd(f, frame_type);
	request(bout, f);
	if (req_msg.data_p)
		free(req_msg.data_p);
}

void login()
{
	debug(LOG_INFO, "login frps ...");
	
	char *lg_msg = NULL;
	int len = login_request_marshal(&lg_msg); //marshal login request
	if ( ! lg_msg) {
		debug(LOG_ERR, "login_request_marshal failed");
		assert(lg_msg);
	}

	struct common_conf *c = get_common_config();
	if (c->tcp_mux) {
		// using sid = 3 is only for matching fprs, it will change after using tcp-mux
		sync_session_id(3); 
	}
	
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

	bufferevent_enable(bev, EV_WRITE|EV_READ);
	bufferevent_setcb(bev, NULL, NULL, connect_event_cb, NULL);
}

void send_new_proxy(struct proxy_service *ps)
{
	debug(LOG_DEBUG, "control proxy client: [%s]", ps->proxy_name);

	char *new_proxy_msg = NULL;
	int len = new_proxy_service_marshal(ps, &new_proxy_msg);
	if ( ! new_proxy_msg) {
		debug(LOG_ERR, "proxy service request marshal failed");
		assert(new_proxy_msg);
	}

	send_msg_frp_server(NULL, TypeNewProxy, new_proxy_msg, len, main_ctl->session_id);
	free(new_proxy_msg);
}

int init_main_control() 
{
	main_ctl = calloc(sizeof(struct control), 1);
	assert(main_ctl);
	struct event_base *base = NULL;
	struct evdns_base *dnsbase  = NULL; 
	base = event_base_new();
	if (!base)
		return 1;
	
	dnsbase = evdns_base_new(base, 1);
	if (!dnsbase)
		return 1;

	evdns_base_set_option(dnsbase, "timeout", "1.0");
    // thanks to the following article
    // http://www.wuqiong.info/archives/13/
    evdns_base_set_option(dnsbase, "randomize-case:", "0");//TurnOff DNS-0x20 encoding
    evdns_base_nameserver_ip_add(dnsbase, "180.76.76.76");//BaiduDNS
    evdns_base_nameserver_ip_add(dnsbase, "223.5.5.5");//AliDNS
    evdns_base_nameserver_ip_add(dnsbase, "223.6.6.6");//AliDNS
    evdns_base_nameserver_ip_add(dnsbase, "114.114.114.114");//114DNS

	main_ctl->connect_base = base;
	main_ctl->dnsbase = dnsbase;

	size_t len = (1<<16) + get_header_size();
	request_buf = calloc(1, len);
	assert(request_buf);

	uint32_t *sid = init_sid_index();
	assert(sid);
	main_ctl->session_id = *sid;

	debug(LOG_DEBUG, "Connect Frps with control session ID: %d", main_ctl->session_id);
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
	evdns_base_free(main_ctl->dnsbase, 0);
}

void run_control() {
	start_base_connect();	//with login
	keep_control_alive();
}