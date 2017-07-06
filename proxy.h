#ifndef _PROXY_H_
#define _PROXY_H_

#include <stdint.h>

#include "common.h"

#define IP_LEN 16

struct ftp_pasv {
	int 	code;
	char 	*msg;
	char	ftp_server_ip[IP_LEN];
	int		ftp_server_port;
};

void tcp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void tcp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);
void ftp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void ftp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);

#endif //_PROXY_H_
