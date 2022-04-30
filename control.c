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

static int 
is_client_connected()
{
	return clients_conn_signel;
}

static int 
client_connected(int is_connected)
{
	if (is_connected)
		clients_conn_signel = 1;
	else
		clients_conn_signel = 0;

	return clients_conn_signel;
}

static int 
set_client_work_start(struct proxy_client *client, int is_start_work)
{
	if (is_start_work) {
		assert(client->ps);
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
		free_proxy_client(client);
	} else if (what & BEV_EVENT_CONNECTED) {
		bufferevent_setcb(bev, recv_cb, NULL, client_start_event_cb, client);
		bufferevent_enable(bev, EV_READ|EV_WRITE);
		sync_new_work_connection(bev);
		client_connected(1);
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
ping(struct bufferevent *bev)
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
	
	uint32_t sid = get_main_control()->session_id;
	char *ping_msg = "{}";
	send_enc_msg_frp_server(bev, TypePing, ping_msg, strlen(ping_msg), sid);
}

static void 
sync_new_work_connection(struct bufferevent *bev)
{
	struct bufferevent *bout = bev;
	assert(bout);
	
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

	send_msg_frp_server(bev, TypeNewWorkConn, new_work_conn_request_message, nret, 0);

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
	debug(LOG_DEBUG, "hb_sender_cb");
	if (is_client_connected()) {
		debug(LOG_DEBUG, "ping frps");
		ping(NULL);
	}

	set_ticker_ping_timer(main_ctl->ticker_ping);	
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

static void
dump_all_unknown_encypt(uint8_t *enc_msg, int ilen)
{
	uint8_t *iv 	= get_main_decoder()->iv;
	uint8_t *key 	= get_main_decoder()->key;
	FILE *fout = fopen("unkown.encrypt", "w");
	assert(fout);
	fwrite(iv, 16, 1, fout);	
	fwrite(key, 16, 1, fout);
	fwrite((uint8_t *)&ilen, sizeof(int), 1, fout);
	fwrite(enc_msg, ilen, 1, fout);
	fclose(fout);
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

	uint8_t *dec_msg = NULL;
	size_t len = decrypt_data(buf, ilen, get_main_decoder(), &dec_msg);
	*out = dec_msg;
	debug(LOG_DEBUG, "dec out len %d ", len);

	return len;	
}

static void
print_enc_msg(uint8_t *enc_msg, int len)
{
	printf("enc_msg is [%d]:\n", len);
	for (int i = 0; i < len; i++) {
		if (i%16 == 0)
			printf("\n");
		printf("%1x ", enc_msg[i]);
	}
	printf("\n");
}

static void
handle_control_work(const uint8_t *buf, int len, void *ctx)
{
	uint8_t *frps_cmd = NULL;
	uint8_t cmd_type;
	uint8_t *enc_msg = buf;

	if (!ctx)	
		handle_enc_msg(enc_msg, len, &frps_cmd);
	else
		frps_cmd = buf;

	if (!frps_cmd)	
		return; // only recv iv

	struct msg_hdr *msg = (struct msg_hdr *)frps_cmd;

	cmd_type = msg->type;
	debug(LOG_DEBUG, "cmd_type is %d data is %s", cmd_type, msg->data);
	switch(cmd_type) {
	case TypeReqWorkConn: 
		debug(LOG_DEBUG, "TypeReqWorkConn cmd");
		if (! is_client_connected()) {
			start_proxy_services();
			client_connected(1);
		}
		new_client_connect();
		break;
	case TypeNewProxyResp:
		debug(LOG_DEBUG, "TypeNewProxyResp cmd");
		struct new_proxy_response *npr = new_proxy_resp_unmarshal(msg->data);
		if (npr == NULL) {
			debug(LOG_ERR, "new proxy response buffer unmarshal faild!");
			return;
		}

		proxy_service_resp_raw(npr);
		SAFE_FREE(npr);
		break;
	case TypeStartWorkConn:
		debug(LOG_DEBUG, "TypeStartWorkConn cmd");
		struct start_work_conn_resp *sr = start_work_conn_resp_unmarshal(msg->data); 
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
	case TypePong:
		break;
	default:
		debug(LOG_INFO, "command type dont support: ctx is %d", ctx?1:0);
		print_enc_msg(enc_msg, len);
		dump_all_unknown_encypt(enc_msg, len);
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
	uint8_t *enc_msg = mhdr->data+login_len;
	uint8_t *frps_cmd = NULL;
	int nret = handle_enc_msg(enc_msg, len-login_len-sizeof(struct msg_hdr), &frps_cmd);
	assert(nret > 0);
	// start proxy services must first send
	start_proxy_services();
	client_connected(1);
	debug(LOG_DEBUG, "TypeReqWorkConn cmd, msg :%s", &frps_cmd[8]);
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
		handle_control_work(buf, len, NULL);
	}else {
		// client msg
		debug(LOG_DEBUG, "client message");
		handle_control_work(buf, len, ctx);
	}	
}

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

	unsigned char *buf = calloc(len+1, 1);
	assert(buf);
	evbuffer_remove(input, buf, len);
	debug(LOG_DEBUG, "recv msg from frps %d ", len);
	
	handle_frps_msg(buf, len, ctx);

	SAFE_FREE(buf);
	return;
}

static void 
connect_event_cb (struct bufferevent *bev, short what, void *ctx)
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
	}
}

static void 
keep_control_alive() 
{
	main_ctl->ticker_ping = evtimer_new(main_ctl->connect_base, hb_sender_cb, NULL);
	if ( ! main_ctl->ticker_ping) {
		debug(LOG_ERR, "Ping Ticker init failed!");
		return;
	}
	set_ticker_ping_timer(main_ctl->ticker_ping);
}

static void 
server_dns_cb(int event_code, struct evutil_addrinfo *addr, void *ctx)
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

void 
start_base_connect()
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
	
	send_msg_frp_server(NULL, TypeLogin, lg_msg, len, main_ctl->session_id);
	SAFE_FREE(lg_msg);
}

void 
send_msg_frp_server(struct bufferevent *bev, 
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

	debug(LOG_DEBUG, "send plain msg ----> [%c: %s]", type, msg);
	
	struct msg_hdr *req_msg = calloc(msg_len+sizeof(struct msg_hdr), 1);
	assert(req_msg);
	req_msg->type = type;
	req_msg->length = msg_hton((uint64_t)msg_len);
	memcpy(req_msg->data, msg, msg_len);
	
	bufferevent_write(bout, (uint8_t *)req_msg, msg_len+sizeof(struct msg_hdr));
	
	free(req_msg);
}

void 
send_enc_msg_frp_server(struct bufferevent *bev,
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

	debug(LOG_DEBUG, "send enc msg ----> [%c: %s]", type, msg);
	
	struct msg_hdr *req_msg = calloc(msg_len+sizeof(struct msg_hdr), 1);
	assert(req_msg);
	req_msg->type = type;
	req_msg->length = msg_hton((uint64_t)msg_len);
	memcpy(req_msg->data, msg, msg_len);

	if (get_main_encoder() == NULL) {
		debug(LOG_DEBUG, "init_main_encoder .......");
		struct frp_coder *coder = init_main_encoder();
		bufferevent_write(bout, coder->iv, 16);
	}

	uint8_t *enc_msg = NULL;
	size_t olen = encrypt_data((uint8_t *)req_msg, msg_len+sizeof(struct msg_hdr), get_main_encoder(), &enc_msg);
	assert(olen > 0);
	debug(LOG_DEBUG, "encrypt_data length %d", olen);

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

	send_enc_msg_frp_server(NULL, TypeNewProxy, new_proxy_msg, len, main_ctl->session_id);
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

void 
close_main_control()
{
	assert(main_ctl);
	event_base_dispatch(main_ctl->connect_base);
	event_base_free(main_ctl->connect_base);
	evdns_base_free(main_ctl->dnsbase, 0);
}

void 
run_control() 
{
	start_base_connect();
	keep_control_alive();
}

void 
free_control()
{
	if (!main_ctl)
		return;

	SAFE_FREE(main_ctl);
}
