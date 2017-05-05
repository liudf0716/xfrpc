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

/** @file config.c
    @brief xfrp client config related
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <syslog.h>

#include "ini.h"
#include "uthash.h"

static struct common_conf 	*c_conf;
static struct proxy_client 	*p_clients;


struct common_conf *get_common_config()
{
	return c_conf;
};

void free_common_config()
{
	
};

static int service_handler(void* user, const char* section, const char* name, const char* value)
{
 	struct proxy_client	*pc;
	
	HASH_FIND_STR(p_clients, section, pc);
	if (!pc) {
		pc = new_proxy_client();
		HASH_ADD_STR(p_clients, section, pc);
	} 
	
	pc->
}

static int common_handler(void* user, const char* section, const char* name, const char* value)
{
	struct common_conf *config = (struct common_conf *)user;
	
	#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
	if (MATCH("common", "server_addr")) {
		config->server_addr = strdup(value);
	} else if (MATCH("common", "server_port")) {
		config->server_port = atoi(value);
	} else if (MATCH("common", "http_proxy")) {
		config->http_proxy = strdup(value);
	} else if (MATCH("common", "log_file")) {
		config->log_file = strdup(value);
	} else if (MATCH("common", "log_way")) {
		config->log_way = strdup(value);
	} else if (MATCH("common", "log_level")) {
		config->log_level = strdup(value);
	} else if (MATCH("common", "log_max_days")) {
		config->log_max_days = atoi(value);
	} else if (MATCH("common", "privilege_token")) {
		config->privilege_token = strdup(value);
	} else if (MATCH("common", "heartbeat_interval")) {
		config->heartbeat_interval = atoi(value);
	} else if (MATCH("common", "heartbeat_timeout")) {
		config->heartbeat_timeout = atoi(value);
	} else {
	}
}

void load_config(const char *confile)
{
	c_conf = calloc(sizeof(struct common_conf), 1);
	assert(c_conf);
	if (ini_parse(confile, common_handler, c_conf) < 0) {
		exit(0);
	}
	
	init_parse(confile, service_handle, NULL);
}
