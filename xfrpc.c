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

/** @file xfrpc.c
    @brief xfrpc client
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <errno.h>

#include <syslog.h>

#include <event2/event.h>

#include "commandline.h"
#include "client.h"
#include "config.h"
#include "uthash.h"
#include "control.h"
#include "debug.h"
#include "xfrpc.h"
#include "crypto.h"
#include "msg.h"
#include "utils.h"
#include "tcp_redir.h"
#include "config.h"

static void start_xfrpc_local_service()
{
	// iterate all proxy service to find mstsc service
	// if found, start tcp_redir for it
	struct proxy_service *ps, *ps_tmp;
	struct proxy_service *all_ps = get_all_proxy_services();
	HASH_ITER(hh, all_ps, ps, ps_tmp) {
		if (ps->proxy_type && strcmp(ps->proxy_type, "mstsc") == 0) {
			// start tcp_redir for it
			start_tcp_redir_service(ps);
		}
	}
}

void xfrpc_loop()
{
	start_xfrpc_local_service();
	init_main_control();
	run_control();
	close_main_control();
}
