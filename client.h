// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_CLIENT_H
#define XFRPC_CLIENT_H

#include <stdint.h>
#include "uthash.h"
#include "common.h"
#include "tcpmux.h"

/* Constants */
#define SOCKS5_ADDRES_LEN 20

/* Per-client parser buffer initial capacity */
#define SOCKS5_BUF_INIT_CAP  256
#define XDPI_BUF_INIT_CAP    4096

enum xdpi_service_type {
	NO_XDPI,
	SERVICE_MSTSC,
	SERVICE_RDP,
	SERVICE_VNC,
	SERVICE_SSH,
	SERVICE_TELNET,
	SERVICE_HTTP,
	SERVICE_HTTPS,
};

/* Data Structures */
struct socks5_addr {
	uint8_t     addr[SOCKS5_ADDRES_LEN];
	uint16_t    port;
	uint8_t     type;
	uint8_t     reserve;
};

enum socks5_state {
	SOCKS5_INIT,
	SOCKS5_HANDSHAKE,
	SOCKS5_CONNECT,
	SOCKS5_ESTABLISHED,
};

enum xdpi_state {
	XDPI_INIT,      /* Initial state, waiting for first data */
	XDPI_VERIFIED,  /* Protocol verified successfully */
	XDPI_BLOCKED,   /* Protocol verification failed, connection blocked */
};

struct proxy_client {
	/* Event handling */
	struct event_base    *base;
	struct bufferevent   *ctl_bev;      /* xfrpc proxy <---> frps */
	struct bufferevent   *local_proxy_bev; /* xfrpc proxy <---> local service */
	
	/* Configuration */
	struct base_conf     *bconf;
	struct proxy_service *ps;
	
	/* Stream handling */
	struct tmux_stream   stream;
	uint32_t            stream_id;
	
	/* State flags */
	int                 connected;
	int                 work_started;
	int                 pending_close;   /* local proxy closed, waiting for WUP to send FIN */
	enum xdpi_state     xdpi_state;     /* XDPI verification state */
	
	/* SOCKS5 specific */
	struct socks5_addr  remote_addr;
	enum socks5_state   state;

	/* Initial payload from control message (TypeStartWorkConn) */
	unsigned char       *data_tail;
	size_t              data_tail_size;

	/* Per-client receive buffers (replace rx_ring for protocol parsing) */
	uint8_t            *socks5_buf;     /* SOCKS5 parser staging buffer */
	size_t              socks5_buf_len;
	size_t              socks5_buf_cap;

	uint8_t            *xdpi_buf;       /* XDPI pre-connect staging buffer */
	size_t              xdpi_buf_len;
	size_t              xdpi_buf_cap;

	/* Hash handling */
	UT_hash_handle      hh;
};

struct proxy_service {
	/* Basic configuration */
	char    *proxy_name;
	char    *proxy_type;
	int     use_encryption;
	int     use_compression;

	/* Network configuration */
	char    *local_ip;
	char	*bind_addr;
	int     remote_port;
	int     remote_data_port;
	int     local_port;

	/* Time control */
	int     start_time;    /* Start time (0-23) */
	int     end_time;      /* End time (0-23) */

	/* XDPI service type */
	enum xdpi_service_type service_type;

	/* HTTP/HTTPS specific */
	char    *custom_domains;
	char    *subdomain;
	char    *locations;
	char    *host_header_rewrite;
	char    *http_user;
	char    *http_pwd;

	/* FTP specific */
	char    *ftp_cfg_proxy_name;
	char    *s_root_dir;

	/* Load balancing */
	char    *group;
	char    *group_key;

	/* Plugin configuration */
	char    *plugin;
	char    *plugin_user;
	char    *plugin_pwd;

	/* TCPMux specific */
	char    *multiplexer;        /* Multiplexer type (e.g. "httpconnect") */
	char    *route_by_http_user; /* Route by HTTP user for tcpmux */

	/* Hash handling */
	UT_hash_handle hh;
};

/* Function prototypes */
void start_xfrp_tunnel(struct proxy_client *client);
void del_proxy_client_by_stream_id(uint32_t sid);
struct proxy_client *get_proxy_client(uint32_t sid);
int send_client_data_tail(struct proxy_client *client);
int is_ftp_proxy(const struct proxy_service *ps);
int is_socks5_proxy(const struct proxy_service *ps);
int is_udp_proxy(const struct proxy_service *ps);
int is_tcpmux_proxy(const struct proxy_service *ps);
int has_service_type(const struct proxy_service *ps);
struct proxy_client *new_proxy_client(void);
void clear_all_proxy_client(void);
void xfrp_proxy_event_cb(struct bufferevent *bev, short what, void *ctx);
int xdpi_engine(struct proxy_client *client, const unsigned char *data, size_t len);

#endif // XFRPC_CLIENT_H
