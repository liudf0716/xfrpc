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
	struct common_conf *c_conf = get_common_config();

	if (c_conf->server_addr) free(c_conf->server_addr);
	if (c_conf->http_proxy) free(c_conf->http_proxy);
	if (c_conf->log_file) free(c_conf->log_file);
	if (c_conf->log_way) free(c_conf->log_way);
	if (c_conf->log_level) free(c_conf->log_level);
	if (c_conf->auth_token) free(c_conf->auth_token);
	if (c_conf->privilege_token) free(c_conf->privilege_token);
};

void free_base_config(struct base_conf *bconf)
{
	if (bconf->name) free(bconf->name);
	if (bconf->auth_token) free(bconf->auth_token);
	if (bconf->type) free(bconf->type);
	if (bconf->privilege_token) free(bconf->privilege_token);
	if (bconf->host_header_rewrite) free(bconf->host_header_rewrite);
	if (bconf->http_username) free(bconf->http_username);
	if (bconf->http_password) free(bconf->http_password);
	if (bconf->subdomain) free(bconf->subdomain);
}

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

	debug(LOG_DEBUG, "Section[common]: {server_addr:%s, server_port:%d, auth_token:%s, privilege_token:%s, interval:%d, timeout:%d}",
			 c_conf->server_addr, c_conf->server_port, c_conf->auth_token, c_conf->privilege_token, c_conf->heartbeat_interval, c_conf->heartbeat_timeout);
}

static void dump_proxy_client(const int index, const struct proxy_client *pc)
{
	if (!pc || !pc->bconf)
		return;

	if (NULL == pc->bconf->type) {
		pc->bconf->type = strdup("tcp");
	}
	
	if (1 == pc->bconf->privilege_mode) {
		if (NULL == pc->bconf->privilege_token) {
			debug(LOG_ERR, "Proxy [%s] error: privilege_token must be set when privilege_mode = true", pc->bconf->name);
			exit(0);
		}

        if ((strcmp(pc->bconf->type, "http") != 0) && (strcmp(pc->bconf->type, "https"))) {
		    if (0 > pc->remote_port) {
			    debug(LOG_ERR, "Proxy [%s] error: remote_port must be set when privilege_mode = true", pc->bconf->name);
			    exit(0);
		    }
        }
	}

	if (0 > pc->local_port) {
		debug(LOG_ERR, "Proxy [%s] error: local_port not found", pc->bconf->name);
		exit(0);
	}

	debug(LOG_DEBUG, "Proxy %d: {name:%s, local_port:%d, type:%s}", index, pc->bconf->name, pc->local_port, pc->bconf->type);
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
	bc->use_encryption 	= 0;
	bc->use_gzip		= 0;
	bc->privilege_mode	= 0;
	bc->pool_count		= 0;

	pc->bconf			= bc;
	pc->name			= strdup(name);
	pc->local_port		= -1;
	pc->remote_port		= -1;

	if (c_conf->auth_token)
		bc->auth_token	= strdup(c_conf->auth_token);
	if (c_conf->privilege_token)
		bc->privilege_token = strdup(c_conf->privilege_token);

	return pc;
}

static int service_handler(void *user, const char *section, const char *nm, const char *value)
{
 	struct proxy_client	*pc = NULL;

	if (strcmp(section, "common") == 0)
		return 0;
	
	HASH_FIND_STR(p_clients, section, pc);
	if (!pc) {
		pc = new_proxy_client(section);
		HASH_ADD_KEYPTR(hh, p_clients, pc->name, strlen(pc->name), pc);
		debug(LOG_DEBUG, "Section[%s] not found in p_clients, add pc[%s]",
			  section, pc->name);
	} 
	
	#define MATCH_NAME(s) strcmp(nm, s) == 0
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
	} else if (MATCH_NAME("remote_port")) {
		pc->remote_port = atoi(value);
	} else if (MATCH_NAME("http_user")) {
		pc->bconf->http_username = strdup(value);
	} else if (MATCH_NAME("http_pwd")) {
		pc->bconf->http_password = strdup(value);
	} else if (MATCH_NAME("subdomain")) {
		pc->bconf->subdomain= strdup(value);
	} else if (MATCH_NAME("custom_domains")) {
		pc->custom_domains= strdup(value);
	} else if (MATCH_NAME("locations")) {
		pc->locations= strdup(value);
	} else if (MATCH_NAME("host_header_rewrite")) {
		pc->bconf->host_header_rewrite= strdup(value);
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

	debug(LOG_INFO, "Reading configuration file '%s'", confile);
	
	if (ini_parse(confile, common_handler, c_conf) < 0) {
		debug(LOG_ERR, "Config file parse failed");
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
