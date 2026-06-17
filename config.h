
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_CONFIG_H
#define XFRPC_CONFIG_H

#include "client.h"
#include "common.h"

// Default port definitions
// Remote Desktop ports
#define DEFAULT_MSTSC_PORT                    3389

// Proxy ports
#define DEFAULT_SOCKS5_PORT                   1980

// Plugin service ports
#define XFRPC_PLUGIN_TELNETD_PORT            23
#define XFRPC_PLUGIN_HTTPD_PORT              8000
#define XFRPC_PLUGIN_HTTPD_REMOTE_PORT       8001
#define XFRPC_PLUGIN_INSTALOADER_PORT        10000
#define XFRPC_PLUGIN_INSTALOADER_REMOTE_PORT 10001
#define XFRPC_PLUGIN_YOUTUBEDL_PORT          20002
#define XFRPC_PLUGIN_YOUTUBEDL_REMOTE_PORT   20003

// FTP related definitions
#define FTP_RMT_CTL_PROXY_SUFFIX  "_ftp_remote_ctl_proxy"

/**
 * Common configuration structure for the client
 */
struct common_conf {
	/* Server settings */
	char    *server_addr;          /* default 127.0.0.1 */
	int     server_port;           /* default 7000 */
	char    *auth_token;

	/* OIDC settings */
	char    *auth_method;          /* "token" (default) or "oidc" */
	char    *oidc_client_id;
	char    *oidc_client_secret;
	char    *oidc_audience;
	char    *oidc_scope;
	char    *oidc_token_endpoint_url;
	char    *oidc_trusted_ca_file;
	int     oidc_insecure_skip_verify;
	char    *oidc_proxy_url;

	/* Connection settings */
	int     heartbeat_interval;    /* default 10 */
	int     heartbeat_timeout;     /* default 30 */
	int     tcp_mux;              /* default 0 */

	/* Transport protocol: "tcp" (default), "quic" */
	char    *protocol;

	/* QUIC settings */
	int     quic_bind_port;       /* frps QUIC port, default 0 (disabled) */

	/* TLS settings */
	int     tls_enable;           /* default 0 */
	char    *tls_cert_file;       /* client certificate file (optional) */
	char    *tls_key_file;        /* client private key file (optional) */
	char    *tls_trusted_ca_file; /* CA certificate file for verification */
	char    *tls_server_name;     /* SNI server name (optional) */

	/* Identity settings */
	char    *user;                /* client user name (for visitor auth) */

	/* Environment settings */
	int     is_router;            /* indicates if running on router (OpenWrt/LEDE) */
};

/* Configuration management functions */
struct common_conf *get_common_config(void);
void free_common_config(void);
void load_config(const char *confile);

/* Proxy service management functions */
struct proxy_service *get_proxy_service(const char *proxy_name);
struct proxy_service *get_all_proxy_services(void);
void free_proxy_service(struct proxy_service *ps);
void free_all_proxy_services(void);
int validate_proxy(struct proxy_service *ps);

/* FTP specific functions */
char *get_ftp_data_proxy_name(const char *ftp_proxy_name);

/* Visitor section parser (called from INI handler) */
int parse_visitor_section(const char *section_name, const char *key, const char *value);

#endif //XFRPC_CONFIG_H
