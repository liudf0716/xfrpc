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
    @brief xfrpc client config related
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>

#include "ini.h"
#include "uthash.h"
#include "config.h"
#include "client.h"
#include "debug.h"
#include "msg.h"
#include "utils.h"
#include "version.h"


// define a list of type in array
static const char *valid_types[] = {
	"tcp",
	"udp",
	"socks5",
	"http",
	"https",
	NULL
};

static struct common_conf 	*c_conf;
static struct proxy_service *all_ps;

static void new_ftp_data_proxy_service(struct proxy_service *ftp_ps);

struct common_conf *
get_common_config()
{
	return c_conf;
};

void 
free_common_config()
{
	struct common_conf *c_conf = get_common_config();

	if (c_conf->server_addr) free(c_conf->server_addr);
	if (c_conf->auth_token) free(c_conf->auth_token);
};

static int 
is_true(const char *val)
{
	if (val && (strcmp(val, "true") == 0 || strcmp(val, "1") == 0))
		return 1;
		
	return 0;
}

static const char *
get_valid_type(const char *val)
{
	if (!val)
		return NULL;
	
	#define MATCH_VALUE(s) strcmp(val, s) == 0
	// iterate the valid_types array
	for (int i = 0; valid_types[i]; i++) {
		if (MATCH_VALUE(valid_types[i])) {
			return valid_types[i];
		}
	}
	
	return NULL;
}

static void 
dump_common_conf()
{
	if(! c_conf) {
		debug(LOG_ERR, "Error: c_conf is NULL");
		return;
	}

	debug(LOG_DEBUG, "Section[common]: {server_addr:%s, server_port:%d, auth_token:%s, interval:%d, timeout:%d}",
			 c_conf->server_addr, c_conf->server_port, c_conf->auth_token, 
			 c_conf->heartbeat_interval, c_conf->heartbeat_timeout);
}

static void 
dump_proxy_service(const int index, struct proxy_service *ps)
{
	if (!ps)
		return;
	
	if (NULL == ps->proxy_type) {
		ps->proxy_type = strdup("tcp");
		assert(ps->proxy_type);
	} else if (strcmp(ps->proxy_type, "ftp") == 0) {
		new_ftp_data_proxy_service(ps);
	}

	if (!validate_proxy(ps)) {
		debug(LOG_ERR, "Error: validate_proxy failed");
		exit(-1);
	}

	debug(LOG_DEBUG, 
		"Proxy service %d: {name:%s, local_port:%d, type:%s, use_encryption:%d, use_compression:%d, custom_domains:%s, subdomain:%s, locations:%s, host_header_rewrite:%s, http_user:%s, http_pwd:%s}",
		index,
		ps->proxy_name,
		ps->local_port,
		ps->proxy_type,
		ps->use_encryption,
		ps->use_compression,
		ps->custom_domains,
		ps->subdomain,
		ps->locations,
		ps->host_header_rewrite,
		ps->http_user,
		ps->http_pwd);
}

static void 
dump_all_ps()
{
	struct proxy_service *ps = NULL, *tmp = NULL;
	
	int index = 0;
	HASH_ITER(hh, all_ps, ps, tmp) {
		dump_proxy_service(index++, ps);
	}
}

static struct proxy_service *
new_proxy_service(const char *name)
{
	if (! name)
		return NULL;

	struct proxy_service *ps = (struct proxy_service *)calloc(sizeof(struct proxy_service), 1);
	assert(ps);
	assert(c_conf);

	ps->proxy_name 			= strdup(name);
	ps->ftp_cfg_proxy_name	= NULL;
	assert(ps->proxy_name);

	ps->proxy_type 			= NULL;
	ps->use_encryption 		= 0;
	ps->local_port			= 0;
	ps->remote_port			= 0;
	ps->remote_data_port	= 0;
	ps->use_compression 	= 0;
	ps->use_encryption		= 0;

	ps->custom_domains		= NULL;
	ps->subdomain			= NULL;
	ps->locations			= NULL;
	ps->host_header_rewrite	= NULL;
	ps->http_user			= NULL;
	ps->http_pwd			= NULL;

	ps->group				= NULL;
	ps->group_key			= NULL;

	ps->plugin				= NULL;
	ps->plugin_user			= NULL;
	ps->plugin_pwd			= NULL;

	ps->s_root_dir			= NULL;

	return ps;
}

// create a new proxy service with suffix "_ftp_data_proxy"
static void 
new_ftp_data_proxy_service(struct proxy_service *ftp_ps)
{
	struct proxy_service *ps = NULL;
	char *ftp_data_proxy_name = get_ftp_data_proxy_name((const char *)ftp_ps->proxy_name);

	HASH_FIND_STR(all_ps, ftp_data_proxy_name, ps);
	if (!ps) {
		ps = new_proxy_service(ftp_data_proxy_name);
		if (! ps) {
			debug(LOG_ERR, 
				"cannot create ftp data proxy service, it should not happenned!");
			exit(0);
		}
		
		ps->ftp_cfg_proxy_name = strdup(ftp_ps->proxy_name);
		assert(ps->ftp_cfg_proxy_name);

		ps->proxy_type = strdup("tcp");
		ps->remote_port = ftp_ps->remote_data_port;
		ps->local_ip = ftp_ps->local_ip;
		ps->local_port = 0; //will be init in working tunnel connectting

		HASH_ADD_KEYPTR(hh, all_ps, ps->proxy_name, strlen(ps->proxy_name), ps);
	}

	free(ftp_data_proxy_name);
}

int
validate_proxy(struct proxy_service *ps)
{
	if (!ps || !ps->proxy_name || !ps->proxy_type)
		return 0;

	if (strcmp(ps->proxy_type, "socks5") == 0) {
		if (ps->remote_port == 0) {
			debug(LOG_ERR, "Proxy [%s] error: remote_port not found", ps->proxy_name);
			return 0;
		}
	} else if (strcmp(ps->proxy_type, "tcp") == 0 || strcmp(ps->proxy_type, "udp") == 0) {
		if (ps->local_port == 0 || ps->local_ip == NULL) {
			debug(LOG_ERR, "Proxy [%s] error: local_port or local_ip not found", ps->proxy_name);
			return 0;
		}
	} else if (strcmp(ps->proxy_type, "http") == 0 || strcmp(ps->proxy_type, "https") == 0) {
		if (ps->local_port == 0 || ps->local_ip == NULL) {
			debug(LOG_ERR, "Proxy [%s] error: local_port or local_ip not found", ps->proxy_name);
			return 0;
		}
		// custom_domains and subdomain can not be set at the same time
		// but one of them must be set
		if (ps->custom_domains && ps->subdomain) {
			debug(LOG_ERR, "Proxy [%s] error: custom_domains and subdomain can not be set at the same time", ps->proxy_name);
			return 0;
		} else if (!ps->custom_domains && !ps->subdomain) {
			debug(LOG_ERR, "Proxy [%s] error: custom_domains or subdomain must be set", ps->proxy_name);
			return 0;
		}
	} else {
		debug(LOG_ERR, "Proxy [%s] error: proxy_type not found", ps->proxy_name);
		return 0;
	}

	return 1;
}

static int 
add_user_and_set_password(const char *username, const char *password) 
{
    // Check if the user already exists
    struct passwd *pw = getpwnam(username);
    if (pw != NULL) {
		debug (LOG_ERR, "User %s already exists\n", username);
        return -1;
    }

    // Create the new user with useradd command
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "sudo useradd -m -s /bin/bash %s", username);
    int ret = system(cmd);
    if (ret != 0) {
		debug (LOG_ERR, "Failed to create user %s\n", username);
        return -1;
    }

    // Set the user's password with passwd command
    snprintf(cmd, sizeof(cmd), "echo '%s:%s' | sudo chpasswd", username, password);
    ret = system(cmd);
    if (ret != 0) {
		debug (LOG_ERR, "Failed to set password for user %s\n", username);
        return -1;
    }

    // Add the user to the sudo group with usermod command
    snprintf(cmd, sizeof(cmd), "sudo usermod -aG sudo %s", username);
    ret = system(cmd);
    if (ret != 0) {
		debug (LOG_ERR, "Failed to add user %s to sudo group\n", username);
        return -1;
    }
	
	debug (LOG_DEBUG, "User %s added successfully\n", username);
    return 0;
}

// Common defaults structure
static struct plugin_defaults {
	const char *name;
	int local_port;
	int remote_port;
	const char *local_ip;
} plugins[] = {
	{"telnetd", XFRPC_PLUGIN_TELNETD_PORT, 0, "127.0.0.1"},
	{"instaloader", XFRPC_PLUGIN_INSTALOADER_PORT, XFRPC_PLUGIN_INSTALOADER_REMOTE_PORT, "127.0.0.1"},
	{"instaloader_client", XFRPC_PLUGIN_INSTALOADER_PORT, XFRPC_PLUGIN_INSTALOADER_REMOTE_PORT, "0.0.0.0"},
	{"youtubedl", XFRPC_PLUGIN_YOUTUBEDL_PORT, XFRPC_PLUGIN_YOUTUBEDL_REMOTE_PORT, "127.0.0.1"},
	{"httpd", XFRPC_PLUGIN_HTTPD_PORT, XFRPC_PLUGIN_HTTPD_REMOTE_PORT, "127.0.0.1"},
	{NULL, 0, 0, NULL}
};

/**
 * @brief Process plugin-specific configuration settings
 *
 * @param ps Pointer to proxy service structure containing plugin configuration
 * 
 * This function handles configuration for supported plugins:
 * - telnetd: Telnet daemon plugin
 * - instaloader: Instagram downloader service
 * - instaloader_client: Instagram downloader client
 * - youtubedl: YouTube downloader service
 * - httpd: HTTP server plugin
 *
 * For each plugin it sets default values for:
 * - Local port
 * - Remote port (if applicable) 
 * - Local IP address
 * - Additional plugin-specific settings
 *
 * @note Will exit early if ps is NULL or no plugin is specified
 */
static void process_plugin_conf(struct proxy_service *ps) 
{
	if (!ps || !ps->plugin)
		return;

	// Find matching plugin configuration
	for (int i = 0; plugins[i].name != NULL; i++) {
		if (strcmp(ps->plugin, plugins[i].name) == 0) {
			if (ps->local_port == 0)
				ps->local_port = plugins[i].local_port;
			if (ps->local_ip == NULL)
				ps->local_ip = strdup(plugins[i].local_ip);
			if (plugins[i].remote_port && ps->remote_port == 0)
				ps->remote_port = plugins[i].remote_port;

			// Plugin-specific additional configuration
			if (strcmp(plugins[i].name, "telnetd") == 0) {
				if (ps->plugin_user && ps->plugin_pwd) {
					add_user_and_set_password(ps->plugin_user, ps->plugin_pwd);
				}
			} else if (strcmp(plugins[i].name, "httpd") == 0) {
				if (ps->s_root_dir == NULL)
					ps->s_root_dir = strdup("/var/www/html");
			}
			return;
		}
	}

	debug(LOG_INFO, "plugin %s is not supported", ps->plugin);
}

/**
 * @brief Handles parsing of proxy service configuration sections
 *
 * @param user User data pointer (unused)
 * @param sect Section name from config file
 * @param nm Parameter name
 * @param value Parameter value
 * @return int Returns 1 if parameter was handled, 0 otherwise
 *
 * This function processes configuration parameters for proxy services including:
 * - Basic settings (type, ports, encryption)
 * - HTTP/HTTPS specific settings (domains, auth)
 * - Plugin configurations
 * - Group settings
 */
static int proxy_service_handler(void *user, const char *sect, const char *nm, const char *value)
{
	// Skip common section
	if (strcmp(sect, "common") == 0) {
		return 0;
	}

	// Find or create proxy service
	struct proxy_service *ps = NULL;
	HASH_FIND_STR(all_ps, sect, ps);
	if (!ps) {
		ps = new_proxy_service(sect);
		if (!ps) {
			debug(LOG_ERR, "Failed to create proxy service");
			exit(0);
		}
		HASH_ADD_KEYPTR(hh, all_ps, ps->proxy_name, strlen(ps->proxy_name), ps);
	}

	#define MATCH_NAME(s) strcmp(nm, s) == 0
	#define SET_STRING_VALUE(field) do { \
		ps->field = strdup(value); \
		assert(ps->field); \
	} while(0)

	// Process configuration parameters
	if (MATCH_NAME("type")) {
		if (!get_valid_type(value)) {
			debug(LOG_ERR, "Unsupported proxy type: %s", value);
			exit(0);
		}
		SET_STRING_VALUE(proxy_type);
	}
	else if (MATCH_NAME("local_ip")) SET_STRING_VALUE(local_ip);
	else if (MATCH_NAME("local_port")) ps->local_port = atoi(value);
	else if (MATCH_NAME("remote_port")) ps->remote_port = atoi(value);
	else if (MATCH_NAME("remote_data_port")) ps->remote_data_port = atoi(value);
	else if (MATCH_NAME("use_encryption")) ps->use_encryption = is_true(value);
	else if (MATCH_NAME("use_compression")) ps->use_compression = is_true(value);
	else if (MATCH_NAME("http_user")) SET_STRING_VALUE(http_user);
	else if (MATCH_NAME("http_pwd")) SET_STRING_VALUE(http_pwd);
	else if (MATCH_NAME("subdomain")) SET_STRING_VALUE(subdomain);
	else if (MATCH_NAME("custom_domains")) SET_STRING_VALUE(custom_domains);
	else if (MATCH_NAME("locations")) SET_STRING_VALUE(locations);
	else if (MATCH_NAME("host_header_rewrite")) SET_STRING_VALUE(host_header_rewrite);
	else if (MATCH_NAME("group")) SET_STRING_VALUE(group);
	else if (MATCH_NAME("group_key")) SET_STRING_VALUE(group_key);
	else if (MATCH_NAME("plugin")) SET_STRING_VALUE(plugin);
	else if (MATCH_NAME("plugin_user")) SET_STRING_VALUE(plugin_user);
	else if (MATCH_NAME("plugin_pwd")) SET_STRING_VALUE(plugin_pwd);
	else if (MATCH_NAME("root_dir")) SET_STRING_VALUE(s_root_dir);
	else {
		debug(LOG_ERR, "Unknown option %s in section %s", nm, sect);
		return 0;
	}

	// Special handling for socks5 and plugin configurations
	if (ps->proxy_type) {
		if (strcmp(ps->proxy_type, "socks5") == 0) {
			if (ps->remote_port == 0) ps->remote_port = DEFAULT_SOCKS5_PORT;
			if (!ps->group) SET_STRING_VALUE(group);
		}
		else if (strcmp(ps->proxy_type, "tcp") == 0) {
			process_plugin_conf(ps);
		}
	}

	return 1;
}

/**
 * @brief Handles parsing of the common section configuration parameters
 *
 * @param user Pointer to the common_conf structure to populate
 * @param section Current section name being parsed
 * @param name Parameter name being parsed
 * @param value Parameter value being parsed
 * @return int Returns 1 if parameter was handled, 0 otherwise
 *
 * This function processes the following common configuration parameters:
 * - server_addr: Server address to connect to
 * - server_port: Server port number
 * - heartbeat_interval: Interval between heartbeat messages
 * - heartbeat_timeout: Timeout for heartbeat responses
 * - token: Authentication token
 * - tcp_mux: TCP multiplexing flag
 *
 * @note Uses assert() to verify memory allocations
 */
static int common_handler(void *user, const char *section, const char *name, const char *value)
{
	struct common_conf *config = (struct common_conf *)user;
	
	#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
	
	if (MATCH("common", "server_addr")) {
		SAFE_FREE(config->server_addr);
		config->server_addr = strdup(value);
		assert(config->server_addr);
	} 
	else if (MATCH("common", "server_port")) {
		config->server_port = atoi(value);
	}
	else if (MATCH("common", "heartbeat_interval")) {
		config->heartbeat_interval = atoi(value);
	}
	else if (MATCH("common", "heartbeat_timeout")) {
		config->heartbeat_timeout = atoi(value);
	}
	else if (MATCH("common", "token")) {
		SAFE_FREE(config->auth_token);
		config->auth_token = strdup(value);
		assert(config->auth_token);
	}
	else if (MATCH("common", "tcp_mux")) {
		config->tcp_mux = !!atoi(value); // Convert to boolean
	}
	
	return 1;
}

/**
 * @brief Initializes common configuration with default values
 *
 * @param config Pointer to common_conf structure to initialize
 *
 * Default values set:
 * - server_addr: "0.0.0.0"
 * - server_port: 7000 
 * - heartbeat_interval: 30 seconds
 * - heartbeat_timeout: 90 seconds
 * - tcp_mux: enabled (1)
 * - is_router: disabled (0)
 *
 * @note Exits program if memory allocation fails (via assert)
 * @note Does nothing if config pointer is NULL
 */
static void init_common_conf(struct common_conf *config) {
	if (!config) {
		return;
	}

	// Set default values
	config->server_addr = strdup("127.0.0.1");
	assert(config->server_addr);
	
	config->server_port = 7000;
	config->heartbeat_interval = 30;
	config->heartbeat_timeout = 90;
	config->tcp_mux = 1;
	config->is_router = 0;
}

/**
 * @brief Creates a FTP data proxy name by appending a suffix to the control proxy name
 *
 * @param ftp_proxy_name The base FTP proxy name to extend
 * @return char* A newly allocated string containing the FTP data proxy name
 * 
 * @note The returned string must be freed by the caller
 * @note Function will assert if memory allocation fails
 */
char *get_ftp_data_proxy_name(const char *ftp_proxy_name) {
	if (!ftp_proxy_name) {
		return NULL;
	}

	const char *suffix = FTP_RMT_CTL_PROXY_SUFFIX;
	size_t total_len = strlen(ftp_proxy_name) + strlen(suffix) + 1;
	
	char *data_proxy_name = (char *)calloc(1, total_len);
	assert(data_proxy_name);

	snprintf(data_proxy_name, total_len, "%s%s", ftp_proxy_name, suffix);
	
	return data_proxy_name;
}

/**
 * @brief Validates heartbeat configuration parameters
 *
 * Ensures heartbeat interval is positive and timeout is greater than interval.
 * Exits the program if validation fails.
 */
static void validate_heartbeat_config(void) {
	if (c_conf->heartbeat_interval <= 0) {
		debug(LOG_ERR, "Error: heartbeat_interval must be positive");
		exit(0);
	}

	if (c_conf->heartbeat_timeout < c_conf->heartbeat_interval) {
		debug(LOG_ERR, "Error: heartbeat_timeout must be greater than heartbeat_interval");
		exit(0);
	}
}

/**
 * @brief Loads and parses the configuration file for the xfrpc client
 *
 * @param confile Path to the configuration file to be loaded
 *
 * This function:
 * 1. Initializes the common configuration structure
 * 2. Parses the common section of the config file
 * 3. Validates heartbeat settings
 * 4. Parses the proxy service sections
 * 5. Dumps the configuration for debugging
 *
 * @note Exits the program if configuration parsing fails or validation errors occur
 */
void load_config(const char *confile) {
	// Initialize common configuration
	c_conf = (struct common_conf *)calloc(sizeof(struct common_conf), 1);
	assert(c_conf);
	init_common_conf(c_conf);

	debug(LOG_DEBUG, "Reading configuration file '%s'", confile);

	// Parse common section
	if (ini_parse(confile, common_handler, c_conf) < 0) {
		debug(LOG_ERR, "Config file parse failed");
		exit(0);
	}

	dump_common_conf();

	// Validate heartbeat settings
	validate_heartbeat_config();

	// Parse proxy services
	ini_parse(confile, proxy_service_handler, NULL);

	dump_all_ps();
}

/**
 * @brief Retrieves a proxy service by its name
 *
 * @param proxy_name The name of the proxy service to search for
 * @return struct proxy_service* Pointer to the found proxy service, or NULL if not found
 *
 * @note This function searches through the internal proxy service list
 * @warning The returned pointer should not be freed by the caller
 */
struct proxy_service *get_proxy_service(const char *proxy_name)
{
	if (!proxy_name)
		return NULL;
		
	struct proxy_service *ps = NULL;
	HASH_FIND_STR(all_ps, proxy_name, ps);
	return ps;
}

/**
 * @brief Returns an array of all proxy services configured in the application
 *
 * @return struct proxy_service* Pointer to an array of proxy service structures
 *                              Returns NULL if no services are configured
 *
 * This function retrieves all configured proxy services from the application's
 * configuration. The returned array contains the complete proxy service configurations
 * including ports, protocols, and other service-specific settings.
 */
struct proxy_service *get_all_proxy_services()
{
	return all_ps;
}
