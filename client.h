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

#include <stdbool.h>
#include <stdint.h>

#include "uthash.h"

struct event_base;
struct base_conf;
struct bufferevent;
struct event;
struct new_proxy;

struct proxy_client {
	struct event_base 	*base;
	struct bufferevent	*ctl_bev;
	struct event		*ev_timeout;
	
	struct base_conf	*bconf;
	char	*name; // pointer to bconf->name
	char	*local_ip;
	int		local_port;
	int		remote_port;
	
	char	*custom_domains;
	char	*locations;
	
	//provate arguments
	UT_hash_handle hh;
	struct new_proxy *n_proxy;
};

// When frpc login success, send this message to frps for running a new proxy.
// type NewProxy struct {
// 	ProxyName      string `json:"proxy_name"`
// 	ProxyType      string `json:"proxy_type"`
// 	UseEncryption  bool   `json:"use_encryption"`
// 	UseCompression bool   `json:"use_compression"`

// 	// tcp and udp only
// 	RemotePort int64 `json:"remote_port"`

// 	// http and https only
// 	CustomDomains     []string `json:"custom_domains"`
// 	SubDomain         string   `json:"subdomain"`
// 	Locations         []string `json:"locations"`
// 	HostHeaderRewrite string   `json:"host_header_rewrite"`
// 	HttpUser          string   `json:"http_user"`
// 	HttpPwd           string   `json:"http_pwd"`
// }

struct new_proxy {
	char 	*proxy_name;
	char 	*proxy_type;
	bool 	use_encryption;
	bool	use_compression;

	// tcp and udp only
	int64_t	remote_port;

	// http and https only
	char 	**custom_domains;
	char 	*subdomain;
	char	**locations;
	char	*host_header_rewrite;
	char	*http_user;
	char	*http_pwd;
};

// after frp server accept client connection request
// frp server send xfrp client NoticeUserConn request
// when xfrp client receive that request, it will start
// frp tunnel
void start_frp_tunnel(const struct proxy_client *client);

void del_proxy_client(struct proxy_client *client);

void free_proxy_client(struct proxy_client *client);

#endif
