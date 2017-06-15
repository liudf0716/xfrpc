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

#include <event2/event.h>
#include <event2/dns.h>

#include "commandline.h"
#include "client.h"
#include "config.h"
#include "uthash.h"
#include "control.h"
#include "debug.h"
#include "xfrp_client.h"

static void start_xfrp_client(struct event_base *base, struct evdns_base  *dnsbase)
{
	struct proxy_client *all_pc = get_all_pc();
	struct proxy_client *pc = NULL, *tmp = NULL;
	
	debug(LOG_INFO, "Start xfrp client");
	HASH_ITER(hh, all_pc, pc, tmp) {
		pc->base = base;
		pc->dnsbase = dnsbase;
		control_process(pc);
	}
}

void xfrp_client_loop()
{
	struct event_base *base = NULL;
	struct evdns_base *dnsbase  = NULL; 
	assert(dnsbase);
	
	base = event_base_new();
	if (!base) {
		debug(LOG_ERR, "event_base_new() error");
		exit(0);
	}	
	
	dnsbase = evdns_base_new(base, 1);
	if (!dnsbase) {
		exit(0);
	}
	evdns_base_set_option(dnsbase, "timeout", "1.0");
    // thanks to the following article
    // http://www.wuqiong.info/archives/13/
    evdns_base_set_option(dnsbase, "randomize-case:", "0");//TurnOff DNS-0x20 encoding
    evdns_base_nameserver_ip_add(dnsbase, "180.76.76.76");//BaiduDNS
    evdns_base_nameserver_ip_add(dnsbase, "223.5.5.5");//AliDNS
    evdns_base_nameserver_ip_add(dnsbase, "223.6.6.6");//AliDNS
    evdns_base_nameserver_ip_add(dnsbase, "114.114.114.114");//114DNS
	
	start_xfrp_client(base, dnsbase);
		
	event_base_dispatch(base);
	
	evdns_base_free(dnsbase, 0);
	event_base_free(base);
}
