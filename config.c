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
#include <time.h>

#include <syslog.h>
#include <sys/utsname.h>

#include "ini.h"
#include "uthash.h"
#include "config.h"
#include "client.h"
#include "debug.h"
#include "msg.h"
#include "utils.h"
#include "version.h"

static struct common_conf 	*c_conf;
static struct proxy_client 	*p_clients;
static struct proxy_service *p_services;

static void new_ftp_data_proxy_service(struct proxy_service *ftp_ps);

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
	if (bconf->privilege_token) free(bconf->privilege_token);
	if (bconf->host_header_rewrite) free(bconf->host_header_rewrite);
	if (bconf->subdomain) free(bconf->subdomain);
}

struct proxy_client *get_all_pc()
{
	return p_clients;
}

struct proxy_service *get_all_proxy_services()
{
	return p_services;
}

static int is_true(const char *val)
{
	if (val && (strcmp(val, "true") == 0 || strcmp(val, "1") == 0))
		return 1;
		
	return 0;
}

static const char *get_valid_type(const char *val)
{
	if (!val)
		return NULL;
	
	#define MATCH_VALUE(s) strcmp(val, s) == 0
	if (MATCH_VALUE("tcp") || 
		MATCH_VALUE("http") || 
		MATCH_VALUE("https") || 
		MATCH_VALUE("udp") || 
		MATCH_VALUE("ftp")) { 

		return val;
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

static void dump_proxy_service(const int index, struct proxy_service *ps)
{
	if (!ps)
		return;
	
	if (0 > ps->local_port) {
		debug(LOG_ERR, "Proxy [%s] error: local_port not found", ps->proxy_name);
		exit(0);
	}

	if (NULL == ps->proxy_type) {
		ps->proxy_type = strdup("tcp");
		assert(ps->proxy_type);
	} else if (strcmp(ps->proxy_type, "ftp") == 0) {
		if (ps->remote_data_port <= 0) {
			debug(LOG_ERR, 
				"Proxy [%s] error: remote_data_port must be exist when type is ftp", 
				ps->proxy_name);
			exit(0);
		}

		if (!is_valid_ip_address((const char *)c_conf->server_addr)){
			debug(LOG_ERR, "now ftp proxy only support ip address in [server_addr]");
			exit(0);
		}

		new_ftp_data_proxy_service(ps);
	}

	debug(LOG_DEBUG, 
		"Proxy service %d: {name:%s, local_port:%d, type:%s}", 
		index, 
		ps->proxy_name, 
		ps->local_port, 
		ps->proxy_type);
}

static void dump_all_ps()
{
	struct proxy_service *ps = NULL, *tmp = NULL;
	
	int index = 0;
	HASH_ITER(hh, p_services, ps, tmp) {
		dump_proxy_service(index++, ps);
	}
}

static struct proxy_service *new_proxy_service(const char *name)
{
	if (! name)
		return NULL;

	struct proxy_service *ps = (struct proxy_service *)calloc(sizeof(struct proxy_service), 1);
	assert(ps);
	assert(c_conf);

	ps->proxy_name 			= strdup(name);
	assert(ps->proxy_name);

	ps->proxy_type 			= NULL;
	ps->use_encryption 		= 0;
	ps->local_port			= -1;
	ps->remote_port			= -1;
	ps->remote_data_port	= -1;
	ps->use_compression 	= 0;
	ps->use_encryption		= 0;

	ps->custom_domains		= NULL;
	ps->subdomain			= NULL;
	ps->locations			= NULL;
	ps->host_header_rewrite	= NULL;
	ps->http_user			= NULL;
	ps->http_pwd			= NULL;

	return ps;
}

// create a new proxy service with suffix "_ftp_data_proxy"
static void new_ftp_data_proxy_service(struct proxy_service *ftp_ps)
{
	struct proxy_service *ps = NULL;
	char *ftp_tail_data_name = "_ftp_data_proxy";
	char *ftp_data_proxy_name = (char *)calloc(1, 
								strlen(ftp_ps->proxy_name)+strlen(ftp_tail_data_name)+1);
	assert(ftp_data_proxy_name);
	snprintf(ftp_data_proxy_name, 
		strlen(ftp_ps->proxy_name) + strlen(ftp_tail_data_name) + 1, 
		"%s%s", 
		ftp_ps->proxy_name, 
		ftp_tail_data_name);

	HASH_FIND_STR(p_services, ftp_data_proxy_name, ps);
	if (!ps) {
		ps = new_proxy_service(ftp_data_proxy_name);
		if (! ps) {
			debug(LOG_ERR, 
				"cannot create ftp data proxy service, it should not happenned!");
			exit(0);
		}

		ps->proxy_type = strdup("tcp");
		ps->remote_port = ftp_ps->remote_data_port;
		ps->local_ip = ftp_ps->local_ip;
		ps->local_port = 0; //will be init in working tunnel connectting

		HASH_ADD_KEYPTR(hh, p_services, ps->proxy_name, strlen(ps->proxy_name), ps);
	}

	free(ftp_data_proxy_name);
}

static int 
proxy_service_handler(void *user, const char *sect, const char *nm, const char *value)
{
 	struct proxy_service *ps = NULL;

	char *section = NULL;
	section = strdup(sect);
	assert(section);

	if (strcmp(section, "common") == 0) {
		SAFE_FREE(section);
		return 0;
	}

	HASH_FIND_STR(p_services, section, ps);
	if (!ps) {
		ps = new_proxy_service(section);
		if (! ps) {
			debug(LOG_ERR, "cannot create proxy service, it should not happenned!");
			exit(0);
		}

		HASH_ADD_KEYPTR(hh, p_services, ps->proxy_name, strlen(ps->proxy_name), ps);
	} 
	
	#define MATCH_NAME(s) strcmp(nm, s) == 0
	#define TO_BOOL(v) strcmp(value, "true") ? 0:1

	if (MATCH_NAME("type")) {
		if (! get_valid_type(value)) {
			debug(LOG_ERR, "proxy service type %s is not supportted", value);
			SAFE_FREE(section);
			exit(0);
		}
		ps->proxy_type = strdup(value);
		assert(ps->proxy_type);
	} else if (MATCH_NAME("local_ip")) {
		ps->local_ip = strdup(value);
		assert(ps->local_ip);
	} else if (MATCH_NAME("local_port")) {
		ps->local_port = atoi(value);
	} else if (MATCH_NAME("use_encryption")) {
		ps->use_encryption = is_true(value);
	} else if (MATCH_NAME("remote_port")) {
		ps->remote_port = atoi(value);
	} else if (MATCH_NAME("remote_data_port")) {
		ps->remote_data_port = atoi(value);
	} else if (MATCH_NAME("http_user")) {
		ps->http_user = strdup(value);
		assert(ps->http_user);
	} else if (MATCH_NAME("http_pwd")) {
		ps->http_pwd = strdup(value);
		assert(ps->http_pwd);
	} else if (MATCH_NAME("subdomain")) {
		ps->subdomain = strdup(value);
		assert(ps->http_pwd);
	} else if (MATCH_NAME("custom_domains")) {
		ps->custom_domains = strdup(value);
		assert(ps->custom_domains);
	} else if (MATCH_NAME("locations")) {
		ps->locations = strdup(value);
		assert(ps->locations);
	} else if (MATCH_NAME("host_header_rewrite")) {
		ps->host_header_rewrite = strdup(value);
		assert(ps->host_header_rewrite);
	} else if (MATCH_NAME("use_encryption")) {
		ps->use_encryption = TO_BOOL(value);
	} else if (MATCH_NAME("use_compression")) {
		ps->use_compression = TO_BOOL(value);
	}

	SAFE_FREE(section);
	return 1;
}

static int common_handler(void *user, const char *section, const char *name, const char *value)
{
	struct common_conf *config = (struct common_conf *)user;
	
	#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
	if (MATCH("common", "server_addr")) {
		SAFE_FREE(config->server_addr);
		config->server_addr = strdup(value);
		assert(config->server_addr);
	} else if (MATCH("common", "server_port")) {
		config->server_port = atoi(value);
	} else if (MATCH("common", "http_proxy")) {
		SAFE_FREE(config->http_proxy);
		config->http_proxy = strdup(value);
		assert(config->http_proxy);
	} else if (MATCH("common", "log_file")) {
		SAFE_FREE(config->log_file);
		config->log_file = strdup(value);
		assert(config->log_file);
	} else if (MATCH("common", "log_way")) {
		SAFE_FREE(config->log_way);
		config->log_way = strdup(value);
		assert(config->log_way);
	} else if (MATCH("common", "log_level")) {
		SAFE_FREE(config->log_level);
		config->log_level = strdup(value);
		assert(config->log_level);
	} else if (MATCH("common", "log_max_days")) {
		config->log_max_days = atoi(value);
	} else if (MATCH("common", "privilege_token")) {
		SAFE_FREE(config->privilege_token);
		config->privilege_token = strdup(value);
		assert(config->privilege_token);
	} else if (MATCH("common", "heartbeat_interval")) {
		config->heartbeat_interval = atoi(value);
	} else if (MATCH("common", "heartbeat_timeout")) {
		config->heartbeat_timeout = atoi(value);
	} else if (MATCH("common", "auth_token")) {
		SAFE_FREE(config->auth_token);
		config->auth_token = strdup(value);
		assert(config->auth_token);
	} else if (MATCH("common", "user")) {
		SAFE_FREE(config->user);
		config->user = strdup(value);
		assert(config->user);
	} else if (MATCH("common", "tcp_mux")) {
		config->tcp_mux = 0;	// set tcp_mux to default: false
	}
	return 1;
}

static void init_common_conf(struct common_conf *config)
{
	if (!config)
		return;
	
	config->server_addr			= strdup("0.0.0.0");
	assert(config->server_addr);
	config->server_port			= 7000;
	config->log_file			= strdup("console");
	assert(config->log_file);
	config->log_way				= strdup("console");
	assert(config->log_way);
	config->log_level			= strdup("info");
	assert(config->log_level);
	config->log_max_days		= 3;
	config->heartbeat_interval 	= 30;
	config->heartbeat_timeout	= 60;
	config->tcp_mux				= 0;
	config->user				= NULL;
}

void load_config(const char *confile)
{
	c_conf = (struct common_conf *)calloc(sizeof(struct common_conf), 1);
	assert(c_conf);
	
	init_common_conf(c_conf);

	debug(LOG_DEBUG, "Reading configuration file '%s'", confile);
	
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
	
	ini_parse(confile, proxy_service_handler, NULL);
	
	dump_all_ps();
}
