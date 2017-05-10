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
#include "config.h"
#include "client.h"
#include "debug.h"

static struct common_conf 	*c_conf;
static struct proxy_client 	*p_clients;


struct common_conf *get_common_config()
{
	return c_conf;
};

void free_common_config()
{
	
};

struct proxy_client *get_all_pc()
{
	return p_clients;
}

static int is_true(const char *val)
{
	if (val && (strcmp(val, "true") == 0 || strcmp(val, "1") == 0))
		return 1;
		
	return 0;
}

static char *get_valid_type(const char *val)
{
	if (!val)
		return NULL;
	
	#define MATCH_VALUE(s) strcmp(val, s) == 0
	if (MATCH_VALUE("tcp") || MATCH_VALUE("http") || MATCH_VALUE("https") || MATCH_VALUE("udp")) {
		return strdup(val);
	}
	
	return NULL;
}

static void dump_common_conf()
{
	if(!c_conf) {
		debug(LOG_ERR, "Error: c_conf is NULL");
		return;
	}
	
	debug(LOG_DEBUG, 
		  "common_conf {server_addr:%s,server_port:%d,privilege_token:%s,heartbeat_interval:%d,heartbeat_timeout:%d}",
		 c_conf->server_addr, c_conf->server_port, c_conf->privilege_token, c_conf->heartbeat_interval, c_conf->heartbeat_timeout);
}

static void dump_proxy_client(const int index, const struct proxy_client *pc)
{
	if (!pc || !pc->bconf)
		return;
	
	debug(LOG_DEBUG, "client %d :", index);
	debug(LOG_DEBUG, "base_conf {name:%s,auth_token:%s,type:%s}",
		 pc->bconf->name, pc->bconf->auth_token, pc->bconf->type);
	debug(LOG_DEBUG, "pc {local_ip:%s,local_port:%d}",
		 pc->local_ip, pc->local_port);
}

static void dump_all_pc()
{
	struct proxy_client *s = NULL, *tmp = NULL;
	
	int index = 0;
	HASH_ITER(hh, p_clients, s, tmp) {
		dump_proxy_client(index++, s);
	}
}

static struct proxy_client *new_proxy_client(const char *name)
{
	struct proxy_client *pc = calloc(sizeof(struct proxy_client), 1);
	assert(pc);
	struct base_conf	*bc = calloc(sizeof(struct base_conf), 1);
	assert(bc);
	assert(c_conf);
	
	bc->name 			= strdup(name);
	bc->auth_token 		= strdup(c_conf->auth_token);
	bc->use_encryption 	= 0;
	bc->use_gzip		= 0;
	bc->privilege_mode	= 0;
	bc->pool_count		= 0;
	
	pc->bconf = bc;
	pc->name  = bc->name;
	
	return pc;
}

static int service_handler(void *user, const char *section, const char *name, const char *value)
{
 	struct proxy_client	*pc = NULL;
	
	debug(LOG_DEBUG, "section:%s name:%s value:%s", section, name, value);
	
	if (strcmp(section, "common") == 0)
		return 0;
	
	HASH_FIND_STR(p_clients, section, pc);
	if (!pc) {
		pc = new_proxy_client(section);
		HASH_ADD_STR(p_clients, name, pc);
	} 
	
	#define MATCH_NAME(s) strcmp(name, s) == 0
	if (MATCH_NAME("type")) {
		pc->bconf->type = get_valid_type(value);
	} else if (MATCH_NAME("local_ip")) {
		pc->local_ip = strdup(value);
	} else if (MATCH_NAME("local_port")) {
		pc->local_port = atoi(value);
	} else if (MATCH_NAME("use_encryption")) {
		pc->bconf->use_encryption = is_true(value);
	} else if (MATCH_NAME("use_gzip")) {
		pc->bconf->use_gzip = is_true(value);
	} else if (MATCH_NAME("privilege_mode")) {
		pc->bconf->privilege_mode = is_true(value);
	} else if (MATCH_NAME("pool_count")) {
		pc->bconf->pool_count = atoi(value);
	} 
	
	return 1;
}

static int common_handler(void *user, const char *section, const char *name, const char *value)
{
	struct common_conf *config = (struct common_conf *)user;
	
	#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
	if (MATCH("common", "server_addr")) {
		if (config->server_addr) free(config->server_addr);
		config->server_addr = strdup(value);
	} else if (MATCH("common", "server_port")) {
		config->server_port = atoi(value);
	} else if (MATCH("common", "http_proxy")) {
		config->http_proxy = strdup(value);
	} else if (MATCH("common", "log_file")) {
		if (config->log_file) free(config->log_file);
		config->log_file = strdup(value);
	} else if (MATCH("common", "log_way")) {
		if (config->log_way) free(config->log_way);
		config->log_way = strdup(value);
	} else if (MATCH("common", "log_level")) {
		if (config->log_level) free(config->log_level);
		config->log_level = strdup(value);
	} else if (MATCH("common", "log_max_days")) {
		config->log_max_days = atoi(value);
	} else if (MATCH("common", "privilege_token")) {
		config->privilege_token = strdup(value);
	} else if (MATCH("common", "heartbeat_interval")) {
		config->heartbeat_interval = atoi(value);
	} else if (MATCH("common", "heartbeat_timeout")) {
		config->heartbeat_timeout = atoi(value);
	} else if (MATCH("common", "auth_token")) {
		config->auth_token = strdup(value);
	}
	
	return 1;
}

static void init_common_conf(struct common_conf *config)
{
	if (!config)
		return;
	
	config->server_addr			= strdup("0.0.0.0");
	config->server_port			= 7000;
	config->log_file			= strdup("console");
	config->log_way				= strdup("console");
	config->log_level			= strdup("info");
	config->log_max_days		= 3;
	config->heartbeat_interval 	= 10;
	config->heartbeat_timeout	= 30;
}

void load_config(const char *confile)
{
	c_conf = calloc(sizeof(struct common_conf), 1);
	assert(c_conf);
	
	init_common_conf(c_conf);
	
	debug(LOG_DEBUG, "confile is %s", confile);
	
	if (ini_parse(confile, common_handler, c_conf) < 0) {
		debug(LOG_ERR, "ini file parse failed");
		exit(0);
	}
	
	dump_common_conf();
	
	if (c_conf->heartbeat_interval <= 0) {
		debug(LOG_ERR, "Error: heartbeat_interval <= 0");
		exit(0);
	}
	
	if (c_conf->heartbeat_timeout < c_conf->heartbeat_interval) {
		debug(LOG_ERR, "Error: heartbeat_timeout < heartbeat_interval");
		exit(0);
	}
	
	ini_parse(confile, service_handler, NULL);
	
	dump_all_pc();
}
