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
#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "client.h"
#include "common.h"

#define FTP_RMT_CTL_PROXY_SUFFIX	"_ftp_remote_ctl_proxy"

//client common config
struct common_conf {
	char	*server_addr; 	/* default 0.0.0.0 */
	int		server_port; 	/* default 7000 */
	char	*auth_token;
	int		heartbeat_interval; /* default 10 */
	int		heartbeat_timeout;	/* default 30 */
	int 	tcp_mux;		/* default 0 */

	/* private fields */
	int 	is_router;	// to sign router (Openwrt/LEDE) or not
};

struct common_conf *get_common_config();

void free_common_config();

void load_config(const char *confile);

char *get_ftp_data_proxy_name(const char *ftp_proxy_name);

int is_running_in_router();

struct proxy_service *get_proxy_service(const char *proxy_name);

struct proxy_service *get_all_proxy_services();

#endif //_CONFIG_H_
