#ifndef _PROXY_H_
#define _PROXY_H_

#include <stdint.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include "client.h"
#include "common.h"

#define IP_LEN 16

struct ftp_pasv {
	int 	code;
	char	ftp_server_ip[IP_LEN];
	int		ftp_server_port;
};

struct proxy {
	struct bufferevent 	*bev;
	int 				remote_data_port;	//used in ftp proxy
};

void tcp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void tcp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);
void ftp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void ftp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);
struct proxy *new_proxy_buf(struct bufferevent *bev);

#endif //_PROXY_H_
