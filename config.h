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

/** @file config.h
    @brief xfrpc client config related
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
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

	/* Connection settings */
	int     heartbeat_interval;    /* default 10 */
	int     heartbeat_timeout;     /* default 30 */
	int     tcp_mux;              /* default 0 */

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
int validate_proxy(struct proxy_service *ps);

/* FTP specific functions */
char *get_ftp_data_proxy_name(const char *ftp_proxy_name);

/* Environment check functions */
int is_running_in_router(void);

#endif //XFRPC_CONFIG_H
