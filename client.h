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

#include "uthash.h"

struct event_base;
struct base_conf;
struct bufferevent;
struct event;

struct proxy_client {
	struct event_base 	*base;
	struct event		ev_timeout;
	struct bufferevent	*ctl_bev;
	
	struct base_conf	*bconf;
	char	*name; // pointer to bconf->name
	char	*local_ip;
	int		local_port;
	int		remote_port;
	
	char	*custom_domains;
	char	*locations;
	
	UT_hash_handle hh;
};

// after frp server accept client connection request
// frp server send xfrp client NoticeUserConn request
// when xfrp client receive that request, it will start
// frp tunnel
void start_frp_tunnel(const struct proxy_client *client);

void del_proxy_client(struct proxy_client *client);

void free_proxy_client(struct proxy_client *client);

#endif
