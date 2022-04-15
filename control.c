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
#include "login.h"

static struct control *main_ctl;
static int clients_conn_signel = 0;
static int is_login = 0;

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
	if (is_start_work) {
		assert(client->ps);
		client->work_started = 1;
	}else
		client->work_started = 0;

	return client->work_started;
}

static int is_client_work_started(struct proxy_client *client) {
	return client->work_started && client->ps;
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
		debug(LOG_ERR, "Proxy connect server [%s:%d] error", c_conf->server_addr, c_conf->server_port);
		bufferevent_free(bev);
		free_proxy_client(client);
	} else if (what & BEV_EVENT_CONNECTED) {
		bufferevent_setcb(bev, recv_cb, NULL, client_start_event_cb, client);
		bufferevent_enable(bev, EV_READ|EV_WRITE);
		sync_new_work_connection(bev);
		debug(LOG_INFO, "proxy service start");
	}
}

static void new_client_connect()
{
	struct proxy_client *client = new_proxy_client();
	struct common_conf *c_conf = get_common_config();
	assert(c_conf);
	client->base = main_ctl->connect_base;
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
	assert(all_ps);

	struct proxy_service *ps = NULL, *tmp = NULL;
	
	debug(LOG_INFO, "Start xfrp proxy services ...");
	
	HASH_ITER(hh, all_ps, ps, tmp) {
		if(ps == NULL) {
			debug(LOG_ERR, "proxy service is invalid!");
			return;
		}
		send_new_proxy(ps);
	}
}

static void 
init_msg_writer()
{
	if (! is_encoder_inited()) {
		struct frp_coder * e = init_main_encoder();
		if (e)
			sync_iv(e->iv);
	}
}

static void 
init_msg_reader(unsigned char *iv)
{
	if (! is_decoder_inited()) {
		struct frp_coder *d = init_main_decoder(iv);
		if (!d) {
			debug(LOG_DEBUG, "reader init faild!");
		}
	}
}

static size_t 
request(struct bufferevent *bev, struct frame *f) 
{
	size_t write_len = 0;
	struct bufferevent *bout = NULL;

	if (bev) {
		bout = bev;
	} else {
		bout = main_ctl->connect_bev;
	}

	if ( ! bout)
		return 0;

	write_len = (size_t)f->len;
	if ( 0 == write_len)
		return 0;

	bufferevent_write(bout, f->data, write_len);
	return write_len;
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
	free_frame(f);
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
	if (get_common_config()->tcp_mux) {
		struct frame *f = new_frame(cmdNOP, 0); //ping sid is 0
		assert(f);
		request(bout, f);
		free_frame(f);
	}
	
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

	send_enc_msg_frp_server(bev, TypePong, pong_msg, strlen(pong_msg), sid);
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

	send_msg_frp_server(bev, TypeNewWorkConn, new_work_conn_request_message, nret, f->sid);
	request(bout, f);

	free_frame(f);
	SAFE_FREE(work_c);
}

struct bufferevent *
connect_server(struct event_base *base, const char *name, const int port)
{
	struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	assert(bev);

	if (bufferevent_socket_connect_hostname(bev, 
		main_ctl->dnsbase, 
		AF_INET, 
		name, 
		port) < 0 ) {

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

// return: 0: raw succeed 1: raw failed
static int proxy_service_resp_raw(struct new_proxy_response *npr)
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

static void 
raw_message(struct message *msg, struct bufferevent *bev, struct proxy_client *client)
{
	if (client) {
		if (client->work_started) {
			debug(LOG_DEBUG, "raw client [%s] control message.", client->ps->proxy_name);
		}
	}

	struct start_work_conn_resp *sr = NULL; //used in TypeStartWorkConn
	switch(msg->type) {
		case TypeLoginResp:
			if (msg->data_p == NULL) {
				debug(LOG_ERR, 
					"recved TypeLoginResp but no data, it should be never happend!");
				break;
			}

			struct login_resp *lr = login_resp_unmarshal(msg->data_p);
			if (lr == NULL) {
				debug(LOG_ERR, "login response buffer init faild!");
				return;
			}

			int is_logged = login_resp_check(lr);
#ifdef USEENCRYPTION
			if (is_logged) {
				init_msg_writer();
			}
#endif // USEENCRYPTION

			if ( ! is_logged) {
				debug(LOG_ERR, "xfrp login failed, try again!");
				login();
				SAFE_FREE(lr);
				return;
			}

			SAFE_FREE(lr);
			break;

		case TypeReqWorkConn:
			if (! is_client_connected()) {
				start_proxy_services();
				client_connected(1);
				ping(bev);
			}

			new_client_connect();
			break;

		case TypeNewProxyResp:
			{
				if (msg->data_p == NULL) {
					debug(LOG_ERR, 
						"recved TypeNewProxyResp but no data, it should be never happend!");
					break;
				}

				struct new_proxy_response *npr = new_proxy_resp_unmarshal(msg->data_p);
				if (npr == NULL) {
					debug(LOG_ERR, "new proxy response buffer unmarshal faild!");
					return;
				}

				proxy_service_resp_raw(npr);
				
				SAFE_FREE(npr);
				break;
			}

		case TypeStartWorkConn:
			sr = start_work_conn_resp_unmarshal(msg->data_p); 
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

			client->ps = ps;
			debug(LOG_INFO, 
				"proxy service [%s] [%s:%d] start work connection.", 
				sr->proxy_name, 
				ps->local_ip, 
				ps->local_port);

			start_xfrp_tunnel(client);
			set_client_work_start(client, 1);
			break;
		case TypePong:
			pong(bev, NULL);
			break;
		default:
			break;
	}
	SAFE_FREE(sr);
}

static size_t data_handler(unsigned char *buf, ushort len, struct proxy_client *client)
{
	struct bufferevent *bev = NULL;
	if (client) {
		debug(LOG_DEBUG, "client(%s): recved control data", 
			is_client_work_started(client)?"work":"free");
		bev = client->ctl_bev;
	}
	unsigned char *ret_buf = NULL;
	struct frame *f = NULL;

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

	if (len <= min_buf_len) {
		if (f->cmd == 3) {
			base_control_ping(bev);
		}
		goto DATA_H_END;
	}


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
			if ( ! (msg && msg->data_p)) {
				debug(LOG_ERR, "message received format invalid");
				goto DATA_H_END;
			}
			debug(LOG_DEBUG, "recv <---- %c: %s", msg->type, msg->data_p);

			if (msg->data_p == NULL)
				goto DATA_H_END;

			raw_message(msg, bev, client);
			break;
		default:
			break;
	}

	SAFE_FREE(msg);

DATA_H_END:
	free_frame(f);

	return len;
}

// ctx: if recv_cb was called by common control, ctx is NULL
//		when ctx is not NULL it was called by client struct
static unsigned char 
*multy_recv_buffer_raw(unsigned char *buf, size_t buf_len, size_t *ret_len, void *ctx)
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
			debug(LOG_DEBUG, 
				"client [%s] send all work data to proxy tunnel.", 
				client->ps->proxy_name);
			return NULL;
		}
	}

	for(;;) {
		if (buf_len > split_lv) {
			if (! is_logged()) {
				if (buf[0] == 49) {
					msg_size_t  data_len_bigend;
					data_len_bigend = *(msg_size_t *)(buf + MSG_LEN_I);
					msg_size_t data_len = msg_ntoh(data_len_bigend);

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

static int
handle_enc_msg(uint8_t *enc_msg, int ilen, uint8_t **out)
{
	if (ilen <= 0) {
		debug(LOG_INFO, "enc_msg length should not be %d", ilen);
		return -1;
	}

	uint8_t *buf = enc_msg;
	if ( !is_decoder_inited() && get_block_size() <= ilen) {
		init_main_decoder(buf);
		buf += get_block_size();
		ilen -= get_block_size();
		debug(LOG_DEBUG, "first recv stream message, init decoder iv succeed! %d", ilen);
		if (!ilen) {
			// recv only iv
			debug(LOG_DEBUG, "recv eas1238 iv data");
			return 0;
		}	
	}
	
	

	size_t len = decrypt_data(buf, ilen, get_main_decoder(), out);
	debug(LOG_DEBUG, "dec out len %d ", len);

	if (!get_main_decoder() || !get_main_encoder())
		return len;

	uint8_t *plaintext = "this is a test for crypto test, hhhhhhhhhaaaallllaaaalllaaaa";
	uint8_t *cryptext = NULL, *dectext = NULL;
	len = encrypt_data(plaintext, strlen(plaintext), get_main_decoder(), &cryptext);
	len = decrypt_data(cryptext, len, get_main_decoder(), &dectext);
	if (memcmp(plaintext, dectext, len) != 0)
		debug(LOG_DEBUG, "decrypt failed!=============");
	else
		debug(LOG_DEBUG, "decrypt passed!=============");
	return len;	
}

static int
handle_control_work(const uint8_t *buf, int len)
{
	uint8_t *frps_cmd = NULL;
	uint8_t cmd_type;
	uint8_t *enc_msg = buf;
	int nret = handle_enc_msg(enc_msg, len, &frps_cmd);
	if (!frps_cmd)
		return 0;

	cmd_type = frps_cmd[0];
	switch(cmd_type) {
	case TypeReqWorkConn: 
		debug(LOG_DEBUG, "TypeReqWorkConn cmd");
		start_proxy_services();
		ping(NULL);
		//new_client_connect();
		break;
	case TypeNewProxyResp:
		debug(LOG_DEBUG, "TypeNewProxyResp cmd");
		break;
	default:
		debug(LOG_INFO, "command type dont support");
	}

	free(frps_cmd);
	return 1;
}

static int
handle_login_response(const uint8_t *buf, int len)
{
	struct msg_hdr *mhdr = (struct msg_hdr *)buf;
	if (mhdr->type != TypeLoginResp) {
		debug(LOG_ERR, "type incorrect: it should be login response, but %d", mhdr->type);
		return 0;
	}	
	
	struct login_resp *lres = login_resp_unmarshal(mhdr->data); 
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
	debug(LOG_ERR, "login success! %d len %d", login_len, len);
	if (len-login_len-sizeof(struct msg_hdr) == 0)
		return 1;
	
	// in case, system get 3 packet together 
	debug(LOG_DEBUG, "TypeReqWorkConn cmd");
	uint8_t *enc_msg = mhdr->data+login_len;
	uint8_t *frps_cmd = NULL;
	int nret = handle_enc_msg(enc_msg, len-login_len-sizeof(struct msg_hdr), &frps_cmd);
	assert(nret > 0);
	// start proxy services must first send
	start_proxy_services();
	//ping(NULL);
	assert (frps_cmd[0] == TypeReqWorkConn);
	new_client_connect();

	return 1;
}

static void
handle_frps_msg(unsigned char *buf, int len, void *ctx)
{
	if (!is_login) {
		// login response
		handle_login_response(buf, len);
	}else if (!ctx) {
		// control msg
		debug(LOG_DEBUG, "main control message");
		handle_control_work(buf, len);
	}else {
		// client msg
		debug(LOG_DEBUG, "client message");
	}	
}

// ctx: if recv_cb was called by common control, ctx == NULL
//		else ctx == client struct
static void recv_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	int len = evbuffer_get_length(input);
	debug(LOG_DEBUG, "recv msg from frps %d", len);
	if (len <= 0) {
		return;
	}

	unsigned char *buf = calloc(len+1, 1);
	assert(buf);
	evbuffer_remove(input, buf, len);
	
	handle_frps_msg(buf, len, ctx);

	SAFE_FREE(buf);
	return;
}

static void open_connection_session(struct bufferevent *bev)
{
	struct frame *f = new_frame(cmdSYN, main_ctl->session_id);
	assert(f);

	request(bev, f);
	free_frame(f);
}

static void connect_event_cb (struct bufferevent *bev, short what, void *ctx)
{
	struct common_conf 	*c_conf = get_common_config();
	static int retry_times = 0;
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (retry_times >= 10) { // only try 10 times consecutively
			debug(LOG_ERR, 
				"have retry connect to xfrp server for %d times, exit!", 
				retry_times);

			exit(0);
		}

		retry_times++;
		debug(LOG_ERR, "error: connect server [%s:%d] failed", 
				c_conf->server_addr, 
				c_conf->server_port);
		free_control();
		init_main_control();
		start_base_connect();
		close_main_control();
	} else if (what & BEV_EVENT_CONNECTED) {
		retry_times = 0;

		login();
		// recv login-response message before recving othfer fprs messages, 
		//bufferevent_setcb(bev, recv_cb, NULL, NULL, NULL);
		//bufferevent_enable(bev, EV_READ|EV_WRITE|EV_PERSIST);

	}
}

static void keep_control_alive() 
{
	main_ctl->ticker_ping = evtimer_new(main_ctl->connect_base, hb_sender_cb, NULL);
	if ( ! main_ctl->ticker_ping) {
		debug(LOG_ERR, "Ping Ticker init failed!");
		return;
	}
	set_ticker_ping_timer(main_ctl->ticker_ping);
}

static void server_dns_cb(int event_code, struct evutil_addrinfo *addr, void *ctx)
{
    if (event_code) {
        set_common_server_ip((const char *)evutil_gai_strerror(event_code));
    } else {
        struct evutil_addrinfo *ai;
        if (addr->ai_canonname)
            debug(LOG_DEBUG, "addr->ai_canonname [%s]", addr->ai_canonname);
        for (ai = addr; ai; ai = ai->ai_next) {
            char buf[128];
            const char *s = NULL;
            if (ai->ai_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
                s = evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, 128);
            } else if (ai->ai_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
                s = evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, buf, 128);
            }

            if (s) set_common_server_ip(s);
        }
        if (addr) evutil_freeaddrinfo(addr);
    }
}

void start_base_connect()
{
	struct common_conf *c_conf = get_common_config();
	main_ctl->connect_bev = connect_server(main_ctl->connect_base, 
						c_conf->server_addr, 
						c_conf->server_port);
	if ( ! main_ctl->connect_bev) {
		debug(LOG_ERR, "error: connect server [%s:%d] failed", c_conf->server_addr, c_conf->server_port);
		exit(0);
	}

	debug(LOG_INFO, "connect server [%s:%d]...", c_conf->server_addr, c_conf->server_port);
	bufferevent_enable(main_ctl->connect_bev, EV_WRITE|EV_READ);
	bufferevent_setcb(main_ctl->connect_bev, recv_cb, NULL, connect_event_cb, NULL);
}

void sync_iv(unsigned char *iv)
{
	struct frame *f = new_frame(cmdPSH, main_ctl->session_id);
	assert(f);

	f->len = (ushort) get_encrypt_block_size();
	f->data = calloc(f->len, 1);
	memcpy(f->data, iv, f->len);

	struct bufferevent *bout = main_ctl->connect_bev;
	if ( ! bout) {
		return;
	}

	request(bout, f);
	SAFE_FREE(f->data);
	free_frame(f);
}

void login()
{
	char *lg_msg = NULL;
	int len = login_request_marshal(&lg_msg); //marshal login request
	if ( !lg_msg ) {
		debug(LOG_ERR, 
			"error: login_request_marshal failed, it should never be happenned");
		exit(0);
	}
	
	send_msg_frp_server(NULL, TypeLogin, lg_msg, len, main_ctl->session_id);
	SAFE_FREE(lg_msg);
}

void sync_session_id(uint32_t sid)
{
	struct frame *f = new_frame(cmdNOP, sid);
	assert(f);

	size_t send_len = request(NULL, f);
	debug(LOG_DEBUG, "sync session id %d, len %ld", sid, send_len);
	SAFE_FREE(f);
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
	assert(bout);

	debug(LOG_DEBUG, "send ----> [%c: %s]", type, msg);
	
	struct msg_hdr *req_msg = calloc(msg_len+sizeof(struct msg_hdr), 1);
	assert(req_msg);
	req_msg->type = type;
	req_msg->length = msg_hton((uint64_t)msg_len);
	memcpy(req_msg->data, msg, msg_len);
	
	bufferevent_write(bout, (uint8_t *)req_msg, msg_len+sizeof(struct msg_hdr));
	
	free(req_msg);
}

void send_enc_msg_frp_server(struct bufferevent *bev,
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
	assert(bout);

	debug(LOG_DEBUG, "send ----> [%c: %s]", type, msg);
	
	struct msg_hdr *req_msg = calloc(msg_len+sizeof(struct msg_hdr), 1);
	assert(req_msg);
	req_msg->type = type;
	req_msg->length = msg_hton((uint64_t)msg_len);
	memcpy(req_msg->data, msg, msg_len);


	uint8_t *enc_msg = NULL;
	size_t olen = encrypt_data((uint8_t *)req_msg, msg_len+sizeof(struct msg_hdr), get_main_encoder(), &enc_msg);
	assert(olen > 0);
	debug(LOG_DEBUG, "encrypt_data length %d", olen);

	bufferevent_write(bout, enc_msg, olen);

	free(enc_msg);	
	free(req_msg);
}

struct control *get_main_control() 
{
	return main_ctl;
}

void start_login_frp_server(struct event_base *base)
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

void send_new_proxy(struct proxy_service *ps)
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

	debug(LOG_DEBUG, "control proxy client: [%d : %s : %d]", TypeNewProxy, ps->proxy_name, len);

	send_enc_msg_frp_server(NULL, TypeNewProxy, new_proxy_msg, len, main_ctl->session_id);
	SAFE_FREE(new_proxy_msg);
}

void init_main_control()
{
	if (main_ctl && main_ctl->connect_base) {
		event_base_loopbreak(main_ctl->connect_base);
		free(main_ctl);
	}

	main_ctl = calloc(sizeof(struct control), 1);
	assert(main_ctl);

	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		uint32_t *sid = init_sid_index();
		assert(sid);
		main_ctl->session_id = *sid;

		debug(LOG_DEBUG, "Connect Frps with control session ID: %d", main_ctl->session_id);
	}

	struct event_base *base = NULL;
	struct evdns_base *dnsbase = NULL; 
	base = event_base_new();
	if (! base) {
		debug(LOG_ERR, "error: event base init failed!");
		exit(0);
	}
	main_ctl->connect_base = base;

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

	// if server_addr is ip, done control init.
	if (is_valid_ip_address((const char *)c_conf->server_addr))
		return;
	
	// if server_addr is domain, analyze it to ip for server_ip
	debug(LOG_DEBUG, "Get ip address of [%s] from DNServer", c_conf->server_addr);

	struct evutil_addrinfo hints;
	struct evdns_getaddrinfo_request *dns_req;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = EVUTIL_AI_CANONNAME;
	hints.ai_socktype = SOCK_STREAM;
 	hints.ai_protocol = IPPROTO_TCP;

	dns_req = evdns_getaddrinfo(dnsbase, 
							c_conf->server_addr, 
							NULL /* no service name given */,
							&hints, 
							server_dns_cb, 
							NULL);
	if (! dns_req) {
		debug(LOG_ERR, "error: can not analyse the dns of [%s]", c_conf->server_addr);
		exit(0);
	}
}

void close_main_control()
{
	assert(main_ctl);
	event_base_dispatch(main_ctl->connect_base);
	event_base_free(main_ctl->connect_base);
	evdns_base_free(main_ctl->dnsbase, 0);
}

void run_control() 
{
	start_base_connect();
	keep_control_alive();
}

void free_control()
{
	if (!main_ctl)
		return;

	SAFE_FREE(main_ctl);
}
