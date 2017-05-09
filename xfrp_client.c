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

/** @file xfrp_client.c
    @brief xfrp client
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include <json-c/json.h>

#include <syslog.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "commandline.h"
#include "client.h"
#include "config.h"
#include "uthash.h"
#include "control.h"
#include "debug.h"

static void start_xfrp_client(struct event_base *base)
{
	struct proxy_client *all_pc = get_all_pc();
	struct proxy_client *pc = NULL, *tmp = NULL;
	
	HASH_ITER(hh, all_pc, pc, tmp) {
		debug(LOG_INFO, "start control process %s", pc->bconf->name);
		pc->base = base;
		control_process(pc);
	}
}

void xfrp_client_loop(int argc, char **argv)
{
	struct event_base *base = NULL;
	
	base = event_base_new();
	if (!base) {
		debug(LOG_ERR, "event_base_new()");
		exit(0);
	}	
	
	start_xfrp_client(base);
		
	event_base_dispatch(base);
	
	event_base_free(base);
}
