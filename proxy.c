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

struct proxy *
new_proxy_obj(struct bufferevent *bev)
{
	struct proxy *p = (struct proxy *)calloc(1, sizeof(struct proxy));
	assert(p);
	p->bev = bev;
	p->remote_data_port = -1;
	p->proxy_name = NULL;
	return p;
}

void 
free_proxy_obj(struct proxy *p)
{
	SAFE_FREE(p->proxy_name);
	SAFE_FREE(p);
}
