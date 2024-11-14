/*
 * Copyright (C) 2024 Dengfeng Liu <liu_df@qq.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/** @file control.c
 * @brief xfrpc main control protocol implementation
 * @author Copyright (C) 2024 Dengfeng Liu <liudf0716@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
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
#include "proxy.h"

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

struct bufferevent *
connect_udp_server(struct event_base *base)
{
	evutil_socket_t fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		debug(LOG_ERR, "create udp socket failed!");
		return NULL;
	}

	if (evutil_make_socket_nonblocking(fd) < 0) {
		debug(LOG_ERR, "make udp socket nonblocking failed!");
		evutil_closesocket(fd);
		return NULL;
	}

	
	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	assert(bev);
	if (!bev) {
		evutil_closesocket(fd);
		debug(LOG_ERR, "create udp bufferevent failed!");
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
	case TypeUDPPacket:
	{
		struct udp_packet *udp = udp_packet_unmarshal((const char *)msg->data);
		if (!udp) {
			debug(LOG_ERR, "TypeUDPPacket unmarshal failed!");
			break;
		}
		debug(LOG_DEBUG, "recv udp packet from server, content is %s", 
			udp->content);
		assert(ctx);
		struct proxy_client *client = ctx;
		assert(client->ps);
		handle_udp_packet(udp, client);
		SAFE_FREE(udp);
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

static int init_server_connection(struct bufferevent **bev_out, 
								struct event_base *base,
								const char *server_addr, 
								int server_port) 
{
	if (!bev_out || !base || !server_addr) {
		debug(LOG_ERR, "Invalid parameters for server connection");
		return -1;
	}

	// Free existing connection if any
	if (*bev_out) {
		bufferevent_free(*bev_out);
		*bev_out = NULL;
	}

	// Create new connection
	*bev_out = connect_server(base, server_addr, server_port);
	if (!*bev_out) {
		debug(LOG_ERR, "Failed to connect to server [%s:%d]: [%d: %s]",
			  server_addr, server_port, errno, strerror(errno));
		return -1;
	}

	debug(LOG_INFO, "Connecting to server [%s:%d]...", server_addr, server_port);
	return 0;
}

static int setup_server_callbacks(struct bufferevent *bev)
{
	if (!bev) {
		debug(LOG_ERR, "Invalid bufferevent for callback setup");
		return -1;
	}

	bufferevent_enable(bev, EV_WRITE|EV_READ);
	bufferevent_setcb(bev, recv_cb, NULL, connect_event_cb, NULL);
	return 0;
}

static void start_base_connect()
{
	struct common_conf *c_conf = get_common_config();
	if (!c_conf) {
		debug(LOG_ERR, "Failed to get common config");
		exit(1);
	}

	// Initialize server connection
	if (init_server_connection(&main_ctl->connect_bev,
							 main_ctl->connect_base,
							 c_conf->server_addr,
							 c_conf->server_port) != 0) {
		exit(1);
	}

	// Setup callbacks for the connection
	if (setup_server_callbacks(main_ctl->connect_bev) != 0) {
		bufferevent_free(main_ctl->connect_bev);
		exit(1);
	}
}

static int prepare_login_message(char **msg_out, int *len_out) {
	if (!msg_out || !len_out) {
		debug(LOG_ERR, "Invalid output parameters");
		return -1;
	}

	int msg_len = login_request_marshal(msg_out);
	if (msg_len <= 0 || !*msg_out) {
		debug(LOG_ERR, "Failed to marshal login request");
		return -1;
	}

	*len_out = msg_len;
	return 0;
}

void login(void) {
	char *login_msg = NULL;
	int msg_len = 0;

	// Prepare login message
	if (prepare_login_message(&login_msg, &msg_len) != 0) {
		debug(LOG_ERR, "Failed to prepare login message");
		exit(1);
	}

	// Send login request
	debug(LOG_DEBUG, "Sending login request: length=%d", msg_len);
	send_msg_frp_server(NULL, TypeLogin, login_msg, msg_len, &main_ctl->stream);

	// Cleanup
	SAFE_FREE(login_msg);
}

static int prepare_message(const enum msg_type type,
						 const char *msg,
						 const size_t msg_len,
						 struct msg_hdr **msg_out,
						 size_t *total_len)
{
	// Validate inputs
	if (!msg || !msg_out || !total_len) {
		debug(LOG_ERR, "Invalid input parameters");
		return -1;
	}

	// Calculate total message length and allocate memory
	*total_len = msg_len + sizeof(struct msg_hdr);
	struct msg_hdr *req_msg = calloc(*total_len, 1);
	if (!req_msg) {
		debug(LOG_ERR, "Failed to allocate memory for message");
		return -1;
	}

	// Prepare message header and content 
	req_msg->type = type;
	req_msg->length = msg_hton((uint64_t)msg_len);
	memcpy(req_msg->data, msg, msg_len);

	*msg_out = req_msg;
	return 0;
}

void send_msg_frp_server(struct bufferevent *bev,
						const enum msg_type type,
						const char *msg,
						const size_t msg_len,
						struct tmux_stream *stream)
{
	// Get output bufferevent
	struct bufferevent *bout = bev ? bev : main_ctl->connect_bev;
	if (!bout) {
		debug(LOG_ERR, "No valid bufferevent");
		return;
	}

	// Log debug info
	debug(LOG_DEBUG, "Sending message: type=%d, len=%zu", type, msg_len);
	if (msg) {
		debug(LOG_DEBUG, "Message content: %s", msg);
	}

	// Prepare message
	struct msg_hdr *req_msg = NULL;
	size_t total_len = 0;
	if (prepare_message(type, msg, msg_len, &req_msg, &total_len) != 0) {
		return;
	}

	// Send message based on mux configuration
	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		if (tmux_stream_write(bout, (uint8_t *)req_msg, total_len, stream) < 0) {
			debug(LOG_ERR, "Failed to write message through TCP mux");
		}
	} else {
		if (bufferevent_write(bout, (uint8_t *)req_msg, total_len) < 0) {
			debug(LOG_ERR, "Failed to write message directly"); 
		}
	}

	free(req_msg);
}

static int prepare_encrypted_message(const enum msg_type type,
								   const char *msg,
								   const size_t msg_len,
								   uint8_t **enc_msg_out,
								   size_t *enc_len_out)
{
	// Validate inputs
	if (!msg || !enc_msg_out || !enc_len_out) {
		debug(LOG_ERR, "Invalid input parameters");
		return -1;
	}

	// Prepare message header and content
	size_t total_len = msg_len + sizeof(struct msg_hdr);
	struct msg_hdr *req_msg = calloc(total_len, 1);
	if (!req_msg) {
		debug(LOG_ERR, "Failed to allocate memory for message");
		return -1;
	}

	req_msg->type = type;
	req_msg->length = msg_hton((uint64_t)msg_len);
	memcpy(req_msg->data, msg, msg_len);

	// Encrypt message
	uint8_t *enc_msg = NULL;
	size_t enc_len = encrypt_data((uint8_t *)req_msg, total_len, 
								 get_main_encoder(), &enc_msg);
	free(req_msg);

	if (enc_len <= 0 || !enc_msg) {
		debug(LOG_ERR, "Encryption failed");
		return -1;
	}

	*enc_msg_out = enc_msg;
	*enc_len_out = enc_len;
	return 0;
}

static int initialize_encoder(struct bufferevent *bout, struct tmux_stream *stream)
{
	struct frp_coder *coder = init_main_encoder();
	if (!coder) {
		debug(LOG_ERR, "Failed to initialize encoder");
		return -1;
	}

	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		if (tmux_stream_write(bout, coder->iv, 16, stream) < 0) {
			debug(LOG_ERR, "Failed to write IV through TCP mux");
			return -1;
		}
	} else {
		if (bufferevent_write(bout, coder->iv, 16) < 0) {
			debug(LOG_ERR, "Failed to write IV directly");
			return -1;
		}
	}
	return 0;
}

void send_enc_msg_frp_server(struct bufferevent *bev,
							const enum msg_type type,
							const char *msg,
							const size_t msg_len,
							struct tmux_stream *stream)
{
	// Get output bufferevent
	struct bufferevent *bout = bev ? bev : main_ctl->connect_bev;
	if (!bout) {
		debug(LOG_ERR, "No valid bufferevent");
		return;
	}

	// Initialize encoder if needed
	if (!get_main_encoder() && initialize_encoder(bout, stream) != 0) {
		return;
	}

	// Prepare and encrypt message
	uint8_t *enc_msg = NULL;
	size_t enc_len = 0;
	if (prepare_encrypted_message(type, msg, msg_len, &enc_msg, &enc_len) != 0) {
		return;
	}

	// Send encrypted message
	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		if (tmux_stream_write(bout, enc_msg, enc_len, stream) < 0) {
			debug(LOG_ERR, "Failed to write encrypted message through TCP mux");
		}
	} else {
		if (bufferevent_write(bout, enc_msg, enc_len) < 0) {
			debug(LOG_ERR, "Failed to write encrypted message directly");
		}
	}

	free(enc_msg);
}

struct control *
get_main_control() 
{
	return main_ctl;
}

static int init_frp_connection(struct bufferevent **bev_out, struct event_base *base) {
	struct common_conf *c_conf = get_common_config();
	if (!c_conf) {
		debug(LOG_ERR, "Failed to get common config");
		return -1;
	}

	struct bufferevent *bev = connect_server(base, c_conf->server_addr, c_conf->server_port);
	if (!bev) {
		debug(LOG_ERR, "Failed to connect to server [%s:%d]", 
			  c_conf->server_addr, c_conf->server_port);
		return -1;
	}

	*bev_out = bev;
	return 0;
}

void start_login_frp_server(struct event_base *base) 
{
	struct bufferevent *bev = NULL;
	if (init_frp_connection(&bev, base) != 0) {
		return;
	}

	struct common_conf *c_conf = get_common_config();
	debug(LOG_INFO, "Xfrpc login: connecting to server [%s:%d]...", 
		  c_conf->server_addr, c_conf->server_port);

	bufferevent_enable(bev, EV_WRITE|EV_READ);
	bufferevent_setcb(bev, NULL, NULL, connect_event_cb, NULL);
}

static void log_proxy_error(const char *msg, const char *proxy_name) {
	debug(LOG_ERR, "%s%s%s", msg, 
		  proxy_name ? ": " : "", 
		  proxy_name ? proxy_name : "");
}

static int marshal_proxy_service(struct proxy_service *ps, char **msg_out) {
	if (!ps || !msg_out) {
		log_proxy_error("Invalid proxy service or output buffer", NULL);
		return -1;
	}

	int len = new_proxy_service_marshal(ps, msg_out);
	if (len <= 0 || !*msg_out) {
		log_proxy_error("Failed to marshal proxy service", ps->proxy_name);
		return -1;
	}

	return len;
}

void send_new_proxy(struct proxy_service *ps) {
	if (!ps) {
		log_proxy_error("Invalid proxy service", NULL);
		return;
	}

	char *new_proxy_msg = NULL;
	int msg_len = marshal_proxy_service(ps, &new_proxy_msg);
	if (msg_len < 0) {
		return;
	}

	debug(LOG_DEBUG, "Sending new proxy request: type=%d, name=%s, length=%d", 
		  TypeNewProxy, ps->proxy_name, msg_len);

	send_enc_msg_frp_server(NULL, TypeNewProxy, new_proxy_msg, msg_len, 
						   &main_ctl->stream);

	SAFE_FREE(new_proxy_msg);
}

static int init_event_base(struct control *ctl)
{
	struct event_base *base = event_base_new();
	if (!base) {
		debug(LOG_ERR, "Failed to create event base");
		return -1;
	}
	ctl->connect_base = base;
	return 0;
}

static int init_dns_base(struct control *ctl)
{
	struct evdns_base *dnsbase = evdns_base_new(ctl->connect_base, 1);
	if (!dnsbase) {
		debug(LOG_ERR, "Failed to create DNS base");
		return -1;
	}

	// Configure DNS options
	evdns_base_set_option(dnsbase, "timeout", "1.0");
	evdns_base_set_option(dnsbase, "randomize-case:", "0"); // Disable DNS-0x20 encoding

	// Add DNS servers
	const char *dns_servers[] = {
		"180.76.76.76",    // Baidu DNS
		"223.5.5.5",       // AliDNS
		"223.6.6.6",       // AliDNS
		"114.114.114.114"  // 114DNS
	};

	for (size_t i = 0; i < sizeof(dns_servers)/sizeof(dns_servers[0]); i++) {
		evdns_base_nameserver_ip_add(dnsbase, dns_servers[i]);
	}

	ctl->dnsbase = dnsbase;
	return 0;
}

void init_main_control()
{
	// Clean up existing control if present
	if (main_ctl && main_ctl->connect_base) {
		event_base_loopbreak(main_ctl->connect_base);
		free(main_ctl);
	}

	// Allocate and initialize new control structure
	main_ctl = calloc(1, sizeof(struct control));
	if (!main_ctl) {
		debug(LOG_ERR, "Failed to allocate main control");
		exit(1);
	}

	// Initialize event base
	if (init_event_base(main_ctl) != 0) {
		free(main_ctl);
		exit(1);
	}

	// Initialize TCP multiplexing if enabled
	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		init_tmux_stream(&main_ctl->stream, get_next_session_id(), INIT);
	}

	// Skip DNS initialization if server address is IP
	if (is_valid_ip_address(c_conf->server_addr)) {
		return;
	}

	// Initialize DNS base
	if (init_dns_base(main_ctl) != 0) {
		event_base_free(main_ctl->connect_base);
		free(main_ctl);
		exit(1);
	}
}

static void 
free_main_control()
{
	if (main_ctl) {
		free(main_ctl);
		main_ctl = NULL;
	}
}

static void
clear_main_control()
{
	// Validate main control exists
	if (!main_ctl) {
		debug(LOG_ERR, "Cannot clear NULL main control");
		return;
	}

	// Clear event timers
	if (main_ctl->ticker_ping) {
		if (evtimer_del(main_ctl->ticker_ping) < 0) {
			debug(LOG_ERR, "Failed to delete ticker ping timer");
		}
		main_ctl->ticker_ping = NULL;
	}

	if (main_ctl->tcp_mux_ping_event) {
		if (evtimer_del(main_ctl->tcp_mux_ping_event) < 0) {
			debug(LOG_ERR, "Failed to delete TCP mux ping timer"); 
		}
		main_ctl->tcp_mux_ping_event = NULL;
	}

	// Reset connection state
	set_client_status(0);
	is_login = 0;
	pong_time = 0;

	// Clean up resources
	clear_all_proxy_client();
	free_evp_cipher_ctx();

	// Reinitialize TCP multiplexing if enabled
	struct common_conf *conf = get_common_config();
	if (conf && conf->tcp_mux) {
		uint32_t session_id = get_next_session_id();
		init_tmux_stream(&main_ctl->stream, session_id, INIT);
		debug(LOG_DEBUG, "Reinitialized TCP mux stream with session ID %u", session_id);
	}
}

void close_main_control()
{
	if (!main_ctl) {
		debug(LOG_ERR, "main_ctl is NULL");
		return;
	}

	// Clean up resources and state
	clear_main_control();

	// Free event bases
	if (main_ctl->connect_base) {
		if (event_base_dispatch(main_ctl->connect_base) < 0) {
			debug(LOG_ERR, "event_base_dispatch failed");
		}

		if (main_ctl->dnsbase) {
			evdns_base_free(main_ctl->dnsbase, 0);
			main_ctl->dnsbase = NULL;
		}

		event_base_free(main_ctl->connect_base);
		main_ctl->connect_base = NULL;
	}

	// Free the main control structure
	free_main_control();
}

void 
run_control() 
{
	start_base_connect();
}


