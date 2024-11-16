#ifndef XFRPC_CLIENT_H
#define XFRPC_CLIENT_H

#include <stdint.h>
#include "uthash.h"
#include "common.h"
#include "tcpmux.h"

/* Constants */
#define SOCKS5_ADDRES_LEN 20

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
	unsigned char       *data_tail;      /* storage untreated data */
	size_t              data_tail_size;
	
	/* State flags */
	int                 connected;
	int                 work_started;
	
	/* SOCKS5 specific */
	struct socks5_addr  remote_addr;
	enum socks5_state   state;

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
	int     remote_port;
	int     remote_data_port;
	int     local_port;

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
struct proxy_client *new_proxy_client(void);
void clear_all_proxy_client(void);
void xfrp_proxy_event_cb(struct bufferevent *bev, short what, void *ctx);

#endif // XFRPC_CLIENT_H
