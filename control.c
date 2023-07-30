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
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <json-c/json.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>

#include "debug.h"
#include "client.h"
#include "uthash.h"
#include "config.h"
#include "msg.h"
#include "control.h"
#include "uthash.h"
#include "crypto.h"
#include "utils.h"
#include "common.h"
#include "login.h"
#include "tcpmux.h"

static struct control *main_ctl;
static int client_connected = 0;
static int is_login = 0;
static time_t pong_time = 0;

static void new_work_connection(struct bufferevent *bev, struct tmux_stream *stream);
static void recv_cb(struct bufferevent *bev, void *ctx);
static void clear_main_control();
static void start_base_connect();
static void keep_control_alive();

static int 
is_client_connected()
{
	return client_connected;
}

static int 
set_client_status(int is_connected)
{
	if (is_connected)
		client_connected = 1;
	else
		client_connected = 0;

	return client_connected;
}

static int 
set_client_work_start(struct proxy_client *client, int is_start_work)
{
	assert(client->ps);
	if (is_start_work) {
		client->work_started = 1;
	}else
		client->work_started = 0;

	return client->work_started;
}

static void 
client_start_event_cb(struct bufferevent *bev, short what, void *ctx)
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
		debug(LOG_ERR, "Proxy connect server [%s:%d] error: %s", c_conf->server_addr, c_conf->server_port, strerror(errno));
		bufferevent_free(bev);
		del_proxy_client_by_stream_id(client->stream_id);
	} else if (what & BEV_EVENT_CONNECTED) {
		bufferevent_setcb(bev, recv_cb, NULL, client_start_event_cb, client);
		bufferevent_enable(bev, EV_READ|EV_WRITE);
		new_work_connection(bev, &main_ctl->stream);
		set_client_status(1);
		debug(LOG_INFO, "proxy service start");
	}
}

static void 
new_client_connect()
{
	struct proxy_client *client = new_proxy_client();
	struct common_conf *c_conf = get_common_config();
	assert(c_conf);
	client->base = main_ctl->connect_base;
	
	if (c_conf->tcp_mux) {
		debug(LOG_DEBUG, "new client through tcp mux: %d", client->stream_id);
		client->ctl_bev 	= main_ctl->connect_bev;
		send_window_update(client->ctl_bev, &client->stream, 0);
		new_work_connection(client->ctl_bev, &client->stream);
		return;
	}

	struct bufferevent *bev = connect_server(client->base, c_conf->server_addr, c_conf->server_port);
	if (!bev) {
		debug(LOG_DEBUG, "Connect server [%s:%d] failed", c_conf->server_addr, c_conf->server_port);
		return;
	}

	debug(LOG_INFO, "work connection: connect server [%s:%d] ......", c_conf->server_addr, c_conf->server_port);

	client->ctl_bev = bev;
	bufferevent_enable(bev, EV_WRITE);
	bufferevent_setcb(bev, NULL, NULL, client_start_event_cb, client);
}

static void 
start_proxy_services()
{
	struct proxy_service *all_ps = get_all_proxy_services();
	struct proxy_service *ps = NULL, *tmp = NULL;
	
	if (!all_ps) {
		debug(LOG_INFO, "no proxy service configure by user");
		return;
	}

	debug(LOG_INFO, "Start xfrp proxy services ...");
	
	HASH_ITER(hh, all_ps, ps, tmp) {
		if(ps == NULL) {
			debug(LOG_ERR, "proxy service is invalid!");
			return;
		}
		if (strcmp(ps->proxy_type, "mstsc") == 0) {
			debug(LOG_ERR, "no need to send mstsc service!");
			continue;
		}
		send_new_proxy(ps);
	}
}

static void 
ping()
{
	struct bufferevent *bout = main_ctl->connect_bev;

	if ( ! bout) {
		debug(LOG_ERR, "bufferevent is not legal!");
		return;
	}
	
	char *ping_msg = "{}";
	send_enc_msg_frp_server(bout, TypePing, ping_msg, strlen(ping_msg), &main_ctl->stream);
}

static void 
new_work_connection(struct bufferevent *bev, struct tmux_stream *stream)
{
	assert(bev);
	
	/* send new work session regist request to frps*/
	struct work_conn *work_c = new_work_conn();
	work_c->run_id = get_run_id();
	if (! work_c->run_id) {
		debug(LOG_ERR, "cannot found run ID, it should inited when login!");
		SAFE_FREE(work_c);
		return;
	}
	char *new_work_conn_request_message = NULL;
	int nret = new_work_conn_marshal(work_c, &new_work_conn_request_message);
	if (0 == nret) {
		debug(LOG_ERR, "new work connection request run_id marshal failed!");
		return;
	}

	send_msg_frp_server(bev, TypeNewWorkConn, new_work_conn_request_message, nret, stream);

	SAFE_FREE(new_work_conn_request_message);
	SAFE_FREE(work_c);
}

struct bufferevent *
connect_server(struct event_base *base, const char *name, const int port)
{
	struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	assert(bev);

	if (bufferevent_socket_connect_hostname(bev, main_ctl->dnsbase, 
											AF_INET, name, port) < 0 ) {
		bufferevent_free(bev);
		return NULL;
	}
	return bev;
}

static void 
set_ticker_ping_timer(struct event *timeout)
{
	struct timeval tv;
	struct common_conf *c_conf = get_common_config();
	evutil_timerclear(&tv);
	tv.tv_sec = c_conf->heartbeat_interval;
	event_add(timeout, &tv);
}

static void 
hb_sender_cb(evutil_socket_t fd, short event, void *arg)
{
	if (is_client_connected()) {
		debug(LOG_INFO, "ping frps");
		ping(NULL);
	}

	set_ticker_ping_timer(main_ctl->ticker_ping);	
	
	struct common_conf 	*c_conf = get_common_config();
	time_t current_time = time(NULL);
	int interval = current_time - pong_time;
	if (pong_time && interval > c_conf->heartbeat_timeout) {
		debug(LOG_INFO, " interval [%d] greater than heartbeat_timeout [%d]", interval, c_conf->heartbeat_timeout);

		reset_session_id();
		clear_main_control();
		run_control();
		return;
	}
}

// return: 0: raw succeed 1: raw failed
static int 
proxy_service_resp_raw(struct new_proxy_response *npr)
{
	if (npr->error && strlen(npr->error) > 2) {
		debug(LOG_ERR, "error: new proxy response error_field:%s", npr->error);
		return 1;
	}
	
	if ((! npr->proxy_name) || (strlen(npr->proxy_name) <= 0)) {
		debug(LOG_ERR, "error: new proxy response proxy name unmarshal failed!");
		return 1;
	}

	struct proxy_service *ps = NULL;
	ps = get_proxy_service(npr->proxy_name);
	if (! ps) {
		debug(LOG_ERR, "error: proxy_name responsed by TypeNewProxyResp not found!");
		return 1;
	}

	if (! ps->proxy_type) {
		debug(LOG_ERR, "error: proxy_type is NULL, it should be never happend!");
		return 1;
	}

	if (ps->ftp_cfg_proxy_name) {
		struct proxy_service *main_ps = get_proxy_service(ps->ftp_cfg_proxy_name);
		if (main_ps) {
			debug(LOG_DEBUG, "find main ftp proxy service name [%s]", main_ps->proxy_name);
		} else {
			debug(LOG_ERR, "error: cannot find main ftp proxy service!");
			return 1;
		}

		if (npr->remote_port <= 0) {
			debug(LOG_ERR, "error: ftp remote_data_port [%d] that request from server is invalid!", npr->remote_port);
			return 1;
		}
		main_ps->remote_data_port = npr->remote_port;
	}

	return 0;
}

static int
handle_enc_msg(const uint8_t *enc_msg, int ilen, uint8_t **out)
{
	if (ilen <= 0) {
		debug(LOG_INFO, "enc_msg length should not be %d", ilen);
		return -1;
	}

	const uint8_t *buf = enc_msg;
	if ( !is_decoder_inited() && get_block_size() <= ilen) {
		init_main_decoder(buf);
		buf += get_block_size();
		ilen -= get_block_size();
		if (!ilen) {
			// recv only iv
			debug(LOG_DEBUG, "recv eas1238 iv data");
			return 0;
		}	
	}

	uint8_t *dec_msg = NULL;
	size_t len = decrypt_data(buf, ilen, get_main_decoder(), &dec_msg);
	*out = dec_msg;

	return len;	
}

static void
handle_control_work(const uint8_t *buf, int len, void *ctx)
{
	uint8_t *frps_cmd = NULL;
	uint8_t cmd_type;
	const uint8_t *enc_msg = buf;

	if (!ctx) {	
		//debug(LOG_DEBUG, "main control message");
		handle_enc_msg(enc_msg, len, &frps_cmd);
	} else {
		//debug(LOG_DEBUG, "worker message");
		frps_cmd = (uint8_t *)buf;
	}

	if (!frps_cmd)	
		return; // only recv iv

	struct msg_hdr *msg = (struct msg_hdr *)frps_cmd;

	cmd_type = msg->type;
	switch(cmd_type) {
	case TypeReqWorkConn: 
	{
		if (! is_client_connected()) {
			start_proxy_services();
			set_client_status(1);
		}
		new_client_connect();
		break;
	}
	case TypeNewProxyResp:
	{
		struct new_proxy_response *npr = new_proxy_resp_unmarshal((const char *)msg->data);
		if (npr == NULL) {
			debug(LOG_ERR, "new proxy response buffer unmarshal faild!");
			return;
		}

		proxy_service_resp_raw(npr);
		SAFE_FREE(npr);
		break;
	}
	case TypeStartWorkConn:
	{
		struct start_work_conn_resp *sr = start_work_conn_resp_unmarshal((const char *)msg->data); 
		if (! sr) {
			debug(LOG_ERR, 
				"TypeStartWorkConn unmarshal failed, it should never be happend!");
			break;
		}

		struct proxy_service *ps = get_proxy_service(sr->proxy_name);
		if (! ps) {
			debug(LOG_ERR, 
				"TypeStartWorkConn requested proxy service [%s] not found, it should nerver be happend!", 
				sr->proxy_name);
			break;
		}

		assert(ctx);
		struct proxy_client *client = ctx;
		client->ps = ps;
		int r_len = len - sizeof(struct msg_hdr) - msg_hton(msg->length); 
		debug(LOG_DEBUG, 
			"proxy service [%s] [%s:%d] start work connection. remain data length %d", 
			sr->proxy_name, 
			ps->local_ip, 
			ps->local_port,
			r_len);
		if (r_len > 0) {
			client->data_tail_size = r_len;
			client->data_tail = msg->data + msg_hton(msg->length);
			debug(LOG_DEBUG, "data_tail is %s", client->data_tail); 
		}
		start_xfrp_tunnel(client);
		set_client_work_start(client, 1);

		break;
	}
	case TypePong:
		pong_time = time(NULL);
		break;
	default:
		debug(LOG_INFO, "command type dont support: ctx is %d", ctx?1:0);
	}
	
	if (!ctx)
		free(frps_cmd);
}

static int
handle_login_response(const uint8_t *buf, int len)
{
	struct msg_hdr *mhdr = (struct msg_hdr *)buf;
	if (mhdr->type != TypeLoginResp) {
		debug(LOG_ERR, "type incorrect: it should be login response, but %d", mhdr->type);
		return 0;
	}	
	
	struct login_resp *lres = login_resp_unmarshal((const char *)mhdr->data); 
	if (!lres) {
		return 0;
	}

	if (!login_resp_check(lres)) {
		debug(LOG_ERR, "login failed");	
		free(lres);
		return 0;
	}
	free(lres);
	
	is_login = 1;

	int login_len = msg_hton(mhdr->length);
	int ilen = len - login_len - sizeof(struct msg_hdr);
	debug(LOG_ERR, "login success! login_len %d len %d ilen %d", login_len, len, ilen);
	assert(ilen >= 0);
	if (ilen <= 0)
		return 1;
	
	// in case, libevent reveive continue packet together
	struct common_conf 	*c_conf = get_common_config();
	assert(c_conf->tcp_mux == 0);
	uint8_t *enc_msg = mhdr->data + login_len; 
	uint8_t *frps_cmd = NULL;
	int nret = handle_enc_msg(enc_msg, ilen, &frps_cmd);
	assert(nret > 0);
	// start proxy services must first send
	start_proxy_services();
	set_client_status(1);
	debug(LOG_DEBUG, "TypeReqWorkConn cmd, msg :%s", &frps_cmd[8]);
	assert (frps_cmd[0] == TypeReqWorkConn);
	new_client_connect();

	return 1;
}

static void
handle_frps_msg(uint8_t *buf, int len, void *ctx)
{
	if (!is_login) {
		// login response
		handle_login_response(buf, len);
	}else {
		handle_control_work(buf, len, ctx);
	}	
}

static struct tmux_stream abandon_stream;

// ctx: if recv_cb was called by common control, ctx == NULL
//		else ctx == client struct
static void 
recv_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	int len = evbuffer_get_length(input);
	if (len <= 0) {
			return;
	}

	struct common_conf 	*c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		static struct tcp_mux_header tmux_hdr;
		static uint32_t stream_len = 0;
		while (len > 0) {
				struct tmux_stream *cur = get_cur_stream();
				size_t nr = 0;
				if (!cur) {
					memset(&tmux_hdr, 0, sizeof(tmux_hdr));
					uint8_t *data = (uint8_t *)&tmux_hdr;
					if (len < sizeof(tmux_hdr)) {
						debug(LOG_INFO, "len [%d] < sizeof tmux_hdr", len);
						break;
					} 
					nr = bufferevent_read(bev, data, sizeof(tmux_hdr));
					assert(nr == sizeof(tmux_hdr));
					assert(validate_tcp_mux_protocol(&tmux_hdr) > 0);
					len -= nr;
					if (tmux_hdr.type == DATA) {
						uint32_t stream_id = ntohl(tmux_hdr.stream_id);
						stream_len = ntohl(tmux_hdr.length);
						cur = get_stream_by_id(stream_id);
						if (!cur) {
							debug(LOG_INFO, "cur is NULL stream_id is %d, stream_len is %d len is %d", 
										stream_id, stream_len, len);
							if (stream_len > 0)
								cur = &abandon_stream;
							else
								continue;
						}

						if (len == 0) {
							set_cur_stream(cur);
							break;
						}
						if (len >= stream_len) {
							nr = tmux_stream_read(bev, cur, stream_len);
							assert(nr == stream_len);
							len -= stream_len;
						} else {
							nr = tmux_stream_read(bev, cur, len);
							stream_len -= len;
							assert(nr == len);
							set_cur_stream(cur);
							len -= nr;
							break;	
						} 
					}
				} else {
					assert(tmux_hdr.type == DATA);
					if (len >= stream_len ) {
						nr = tmux_stream_read(bev, cur, stream_len);
						assert(nr == stream_len);
						len -= stream_len;
					} else {
						nr = tmux_stream_read(bev, cur, len);
						stream_len -= len;
						assert(nr == len);
						len -= nr;
						break;
					}	
				}
				
				if (cur == &abandon_stream) {
					debug(LOG_INFO, "abandon stream data ...");
					memset(cur , 0, sizeof(abandon_stream));
					set_cur_stream(NULL);
					continue;
				}

				switch(tmux_hdr.type) {
				case DATA:
				case WINDOW_UPDATE:
				{
					handle_tcp_mux_stream(&tmux_hdr, handle_frps_msg);
					break;
				}
				case PING:
					handle_tcp_mux_ping(&tmux_hdr);
					break;
				case GO_AWAY:
					handle_tcp_mux_go_away(&tmux_hdr);
					break;
				default:
					debug(LOG_ERR, "impossible here!!!!");
					exit(-1);
				}

				set_cur_stream(NULL);
		}
	} else {	
		uint8_t *buf = calloc(len, 1);
		assert(buf);
		evbuffer_remove(input, buf, len);

		handle_frps_msg(buf, len, ctx);
		SAFE_FREE(buf);
	}
		

	return;
}

static void 
connect_event_cb (struct bufferevent *bev, short what, void *ctx)
{
	struct common_conf 	*c_conf = get_common_config();
	static int retry_times = 1;
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (retry_times >= 100) {
			debug(LOG_INFO, 
				"have retry connect to xfrp server for %d times, exit?", 
				retry_times);
		}
		sleep(2);
		retry_times++;
		debug(LOG_ERR, "error: connect server [%s:%d] failed %s", 
				c_conf->server_addr, 
				c_conf->server_port,
				strerror(errno));
		reset_session_id();
		clear_main_control();
		run_control();
	} else if (what & BEV_EVENT_CONNECTED) {
		debug(LOG_DEBUG, "xfrp server connected");
		retry_times = 0;
		send_window_update(bev, &main_ctl->stream, 0);
		login();
		
		keep_control_alive();
	}
}

static void 
keep_control_alive() 
{
	debug(LOG_DEBUG, "start keep_control_alive");
	main_ctl->ticker_ping = evtimer_new(main_ctl->connect_base, hb_sender_cb, NULL);
	if ( !main_ctl->ticker_ping) {
		debug(LOG_ERR, "Ping Ticker init failed!");
		return;
	}
	pong_time = time(NULL);
	set_ticker_ping_timer(main_ctl->ticker_ping);
}

static void 
start_base_connect()
{
	struct common_conf *c_conf = get_common_config();
	if (main_ctl->connect_bev)
		bufferevent_free(main_ctl->connect_bev);

	main_ctl->connect_bev = connect_server(main_ctl->connect_base, 
						c_conf->server_addr, 
						c_conf->server_port);
	if ( ! main_ctl->connect_bev) {
		debug(LOG_ERR, "error: connect server [%s:%d] failed: [%d: %s]", 
						c_conf->server_addr, c_conf->server_port, errno, strerror(errno));
		exit(0);
	}

	debug(LOG_INFO, "connect server [%s:%d]...", c_conf->server_addr, c_conf->server_port);
	bufferevent_enable(main_ctl->connect_bev, EV_WRITE|EV_READ);
	bufferevent_setcb(main_ctl->connect_bev, recv_cb, NULL, connect_event_cb, NULL);
}

void 
login()
{
	char *lg_msg = NULL;
	int len = login_request_marshal(&lg_msg); //marshal login request
	if ( !lg_msg ) {
		debug(LOG_ERR, 
			"error: login_request_marshal failed, it should never be happenned");
		exit(0);
	}
	
	send_msg_frp_server(NULL, TypeLogin, lg_msg, len, &main_ctl->stream);
	SAFE_FREE(lg_msg);
}

void 
send_msg_frp_server(struct bufferevent *bev, 
			 const enum msg_type type, 
			 const char *msg, 
			 const size_t msg_len, 
			 struct tmux_stream *stream)
{
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}
	assert(bout);

	

	debug(LOG_DEBUG, "send plain msg ----> [%c: %s]", type, msg);
	
	size_t len = msg_len + sizeof(struct msg_hdr);
	struct msg_hdr *req_msg = calloc(len, 1);
	assert(req_msg);
	req_msg->type = type;
	req_msg->length = msg_hton((uint64_t)msg_len);
	memcpy(req_msg->data, msg, msg_len);
	
	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux)
		tmux_stream_write(bout, (uint8_t *)req_msg, len, stream);
	else
		bufferevent_write(bout, (uint8_t *)req_msg, len);
	
	free(req_msg);
}

void 
send_enc_msg_frp_server(struct bufferevent *bev,
			 const enum msg_type type, 
			 const char *msg, 
			 const size_t msg_len, 
			 struct tmux_stream *stream)
{
	struct bufferevent *bout = NULL;
	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}
	assert(bout);

	struct msg_hdr *req_msg = calloc(msg_len+sizeof(struct msg_hdr), 1);
	assert(req_msg);
	req_msg->type = type;
	req_msg->length = msg_hton((uint64_t)msg_len);
	memcpy(req_msg->data, msg, msg_len);

	struct common_conf *c_conf = get_common_config();
	if (get_main_encoder() == NULL) {
		struct frp_coder *coder = init_main_encoder();
		if (c_conf->tcp_mux) 
			tmux_stream_write(bout, coder->iv, 16, stream);
		else
			bufferevent_write(bout, coder->iv, 16);
	}

	uint8_t *enc_msg = NULL;
	size_t olen = encrypt_data((uint8_t *)req_msg, msg_len+sizeof(struct msg_hdr), get_main_encoder(), &enc_msg);
	assert(olen > 0);
	if (c_conf->tcp_mux)
		tmux_stream_write(bout, enc_msg, olen, stream);
	else
		bufferevent_write(bout, enc_msg, olen);

	free(enc_msg);	
	free(req_msg);
}

struct control *
get_main_control() 
{
	return main_ctl;
}

void 
start_login_frp_server(struct event_base *base)
{
	struct common_conf *c_conf = get_common_config();
	struct bufferevent *bev = connect_server(base, c_conf->server_addr, c_conf->server_port);
	if (!bev) {
		debug(LOG_DEBUG, 
			"Connect server [%s:%d] failed", 
			c_conf->server_addr, 
			c_conf->server_port);
		return;
	}

	debug(LOG_INFO, "Xfrpc login: connect server [%s:%d] ...", c_conf->server_addr, c_conf->server_port);

	bufferevent_enable(bev, EV_WRITE|EV_READ);
	bufferevent_setcb(bev, NULL, NULL, connect_event_cb, NULL);
}

void 
send_new_proxy(struct proxy_service *ps)
{
	if (! ps) {
		debug(LOG_ERR, "proxy service is invalid!");
		return;
	}

	char *new_proxy_msg = NULL;
	int len = new_proxy_service_marshal(ps, &new_proxy_msg);
	if ( ! new_proxy_msg) {
		debug(LOG_ERR, "proxy service request marshal failed");
		return;
	}

	debug(LOG_DEBUG, "control proxy client: [Type %d : proxy_name %s : msg_len %d]", TypeNewProxy, ps->proxy_name, len);

	send_enc_msg_frp_server(NULL, TypeNewProxy, new_proxy_msg, len, &main_ctl->stream);
	SAFE_FREE(new_proxy_msg);
}

void 
init_main_control()
{
	if (main_ctl && main_ctl->connect_base) {
		event_base_loopbreak(main_ctl->connect_base);
		free(main_ctl);
	}

	main_ctl = calloc(sizeof(struct control), 1);
	assert(main_ctl);

	struct common_conf *c_conf = get_common_config();
	struct event_base *base = NULL;
	struct evdns_base *dnsbase = NULL; 
	base = event_base_new();
	if (! base) {
		debug(LOG_ERR, "error: event base init failed!");
		exit(0);
	}
	main_ctl->connect_base = base;
	
	if (c_conf->tcp_mux) {
		init_tmux_stream(&main_ctl->stream, get_next_session_id(), INIT);
	}

	// if server_addr is ip, done control init.
	if (is_valid_ip_address((const char *)c_conf->server_addr))
		return;

	dnsbase = evdns_base_new(base, 1);
	if (! dnsbase) {
		debug(LOG_ERR, "error: evdns base init failed!");
		exit(0);
	}
	main_ctl->dnsbase = dnsbase;

	evdns_base_set_option(dnsbase, "timeout", "1.0");

   	// thanks to the following article
    // http://www.wuqiong.info/archives/13/
    evdns_base_set_option(dnsbase, "randomize-case:", "0");		//TurnOff DNS-0x20 encoding
    evdns_base_nameserver_ip_add(dnsbase, "180.76.76.76");		//BaiduDNS
	evdns_base_nameserver_ip_add(dnsbase, "223.5.5.5");			//AliDNS
    evdns_base_nameserver_ip_add(dnsbase, "223.6.6.6");			//AliDNS
	evdns_base_nameserver_ip_add(dnsbase, "114.114.114.114");	//114DNS
}

static void 
free_main_control()
{
	SAFE_FREE(main_ctl);
	main_ctl = NULL;
}

static void
clear_main_control()
{
	assert(main_ctl);
	if (main_ctl->ticker_ping) evtimer_del(main_ctl->ticker_ping);
	if (main_ctl->tcp_mux_ping_event) evtimer_del(main_ctl->tcp_mux_ping_event);
	clear_all_proxy_client();
	free_evp_cipher_ctx();
	set_client_status(0);
	pong_time = 0;	
	is_login = 0;
	if (get_common_config()->tcp_mux)
		init_tmux_stream(&main_ctl->stream, get_next_session_id(), INIT);
}

void 
close_main_control()
{
	clear_main_control();

	event_base_dispatch(main_ctl->connect_base);
	evdns_base_free(main_ctl->dnsbase, 0);
	event_base_free(main_ctl->connect_base);

	free_main_control();
}

void 
run_control() 
{
	start_base_connect();
}


