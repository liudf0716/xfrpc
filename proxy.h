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

/** @file proxy.h
    @brief xfrp proxy header file
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

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
	char 				*proxy_name;
	int 				remote_data_port;	//used in ftp proxy
};

void tcp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void tcp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);
void ftp_proxy_c2s_cb(struct bufferevent *bev, void *ctx);
void ftp_proxy_s2c_cb(struct bufferevent *bev, void *ctx);
struct proxy *new_proxy_obj(struct bufferevent *bev);
void free_proxy_obj(struct proxy *p);
void set_ftp_data_proxy_tunnel(const char *ftp_proxy_name, 
								struct ftp_pasv *local_fp, 
								struct ftp_pasv *remote_fp);
#endif //_PROXY_H_
