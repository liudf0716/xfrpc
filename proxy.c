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

/** @file proxy.c
    @brief xfrp proxy implemented
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>


#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"
#include "config.h"

/**
 * @brief Creates a new proxy object
 * 
 * Allocates memory for a new proxy structure and initializes its members.
 * The proxy object is used to manage proxy connections and their properties.
 *
 * @param bev Bufferevent associated with the proxy connection
 * @return struct proxy* Pointer to newly created proxy object, NULL if allocation fails
 */
struct proxy *
new_proxy_obj(struct bufferevent *bev)
{
	struct proxy *proxy = (struct proxy *)calloc(1, sizeof(struct proxy));
	if (!proxy) {
		return NULL;
	}
	
	proxy->bev = bev;
	proxy->remote_data_port = -1;
	proxy->proxy_name = NULL;
	
	return proxy;
}

/**
 * @brief Frees a proxy object and its resources
 * 
 * Deallocates memory used by the proxy structure and its members.
 * Should be called when the proxy connection is no longer needed.
 *
 * @param proxy Pointer to the proxy object to be freed
 */
void 
free_proxy_obj(struct proxy *proxy)
{
	if (proxy) {
		SAFE_FREE(proxy->proxy_name);
		SAFE_FREE(proxy);
	}
}
