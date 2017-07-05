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

/** @file client.h
    @brief xfrp client proxy client related
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <stdint.h>

#include "uthash.h"
#include "common.h"

struct event_base;
struct base_conf;
struct bufferevent;
struct event;
struct proxy_service;

struct proxy_client {
	struct event_base 	*base;
	struct bufferevent	*ctl_bev;
	struct bufferevent 	*local_proxy_bev;
	struct event		*ev_timeout;
	
	struct base_conf	*bconf;
	char	*name; // pointer to bconf->name
	char	*local_ip;
	char 	*type;
	int		local_port;
	int		remote_port;
	
	char 	*subdomain;
	char	*locations;
	char	*host_header_rewrite;
	
	//provate arguments
	UT_hash_handle hh;
	int						connected;
	int 					work_started;
	struct 	proxy_service 	*ps;
	unsigned char			*data_tail; // storage untrated data
	size_t					data_tail_size;
};

struct proxy_service {
	char 	*proxy_name;
	char 	*proxy_type;
	int 	use_encryption;
	int		use_compression;

	char	*local_ip;
	int		remote_port;
	int 	local_port;

	// http and https only
	char 	*custom_domains;
	char 	*subdomain;
	char	*locations;
	char	*host_header_rewrite;
	char	*http_user;
	char	*http_pwd;

	//provate arguments
	UT_hash_handle hh;
};

// after frp server accept client connection request
// frp server send xfrp client NoticeUserConn request
// when xfrp client receive that request, it will start
// frp tunnel
// if client has data-tail(not NULL), client value will be changed 
void start_frp_tunnel(struct proxy_client *client);

void del_proxy_client(struct proxy_client *client);

void free_proxy_client(struct proxy_client *client);

struct proxy_service *get_proxy_service(const char *proxy_name);

int send_client_data_tail(struct proxy_client *client);

#endif //_CLIENT_H_
