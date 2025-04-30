// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
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

/**
 * @brief Array of valid proxy service types supported by the application
 */
static const char *valid_types[] = {
	"tcp",
	"udp", 
	"socks5",
	"http",
	"https",
	"iod",
	NULL
};

/**
 * @brief Global configuration structures
 */
static struct common_conf    *c_conf;    /* Common configuration settings */
static struct proxy_service *all_ps;     /* Hash table of all proxy services */

/* Forward declaration */
static void new_ftp_data_proxy_service(struct proxy_service *ftp_ps);

/**
 * @brief Gets the common configuration settings
 * @return struct common_conf* Pointer to common configuration structure
 */
struct common_conf *get_common_config(void)
{
	return c_conf;
}

/**
 * @brief Frees memory used by common configuration
 *
 * Deallocates memory for:
 * - Server address
 * - Authentication token
 */
void free_common_config(void)
{
	struct common_conf *c_conf = get_common_config();
	SAFE_FREE(c_conf->server_addr);
	SAFE_FREE(c_conf->auth_token);
}

/**
 * @brief Checks if a string value represents a boolean true
 *
 * @param val String value to check
 * @return int Returns 1 if true, 0 otherwise
 *
 * Considers "true" and "1" as true values
 */
static int is_true(const char *val)
{
	return (val && (strcmp(val, "true") == 0 || strcmp(val, "1") == 0));
}

/**
 * @brief Validates if a proxy type string is supported
 *
 * @param val Type string to validate
 * @return const char* Returns the valid type string or NULL if invalid
 */
static const char *get_valid_type(const char *val)
{
	if (!val) {
		return NULL;
	}

	for (int i = 0; valid_types[i]; i++) {
		if (strcmp(val, valid_types[i]) == 0) {
			return valid_types[i];
		}
	}

	return NULL;
}

/**
 * @brief Dumps the common configuration settings to debug log
 * 
 * Outputs the following common configuration parameters:
 * - Server address
 * - Server port
 * - Authentication token
 * - Heartbeat interval
 * - Heartbeat timeout
 *
 * @note Does nothing if c_conf is NULL
 */
static void dump_common_conf(void)
{
	if (!c_conf) {
		debug(LOG_ERR, "Error: c_conf is NULL");
		return;
	}

	debug(LOG_DEBUG, "Section[common]: {server_addr:%s, server_port:%d, auth_token:%s, interval:%d, timeout:%d}",
		c_conf->server_addr, 
		c_conf->server_port, 
		c_conf->auth_token, 
		c_conf->heartbeat_interval, 
		c_conf->heartbeat_timeout);
}

/**
 * @brief Dumps configuration details for a single proxy service
 *
 * @param index Index number of the proxy service being dumped
 * @param ps Pointer to proxy service structure to dump
 *
 * This function:
 * 1. Sets default proxy type to "tcp" if none specified
 * 2. Creates data proxy service if type is "ftp"
 * 3. Validates proxy configuration
 * 4. Logs proxy service details including:
 *    - Name, port, type
 *    - Encryption/compression settings
 *    - Domain configurations
 *    - HTTP settings
 *
 * @note Exits program if proxy validation fails
 */
static void dump_proxy_service(const int index, struct proxy_service *ps)
{
	if (!ps)
		return;
	
	// Set default type or handle FTP
	if (!ps->proxy_type) {
		ps->proxy_type = strdup("tcp");
		assert(ps->proxy_type);
	} else if (strcmp(ps->proxy_type, "ftp") == 0) {
		new_ftp_data_proxy_service(ps);
	}

	// Validate configuration
	if (!validate_proxy(ps)) {
		debug(LOG_ERR, "Error: validate_proxy failed");
		exit(-1);
	}

	// Log proxy service details
	debug(LOG_DEBUG, 
		"Proxy service %d: {name:%s, local_port:%d, type:%s, use_encryption:%d, "
		"use_compression:%d, custom_domains:%s, subdomain:%s, locations:%s, "
		"host_header_rewrite:%s, http_user:%s, http_pwd:%s}",
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

/**
 * @brief Dumps debug information for all configured proxy services
 *
 * Iterates through all configured proxy services and prints their configuration
 * details to the debug log. Each proxy service is numbered sequentially starting
 * from 0.
 *
 * Uses the HASH_ITER macro from uthash to safely iterate through the hash table
 * of proxy services. For each service, calls dump_proxy_service() to output its
 * configuration details.
 *
 * @note Requires the all_ps global variable to be properly initialized
 * @see dump_proxy_service() for details on what information is logged
 */
static void dump_all_ps(void)
{
	struct proxy_service *ps = NULL;
	struct proxy_service *tmp = NULL;
	int index = 0;
	
	HASH_ITER(hh, all_ps, ps, tmp) {
		dump_proxy_service(index++, ps);
	}
}

/**
 * @brief Creates and initializes a new proxy service structure
 *
 * @param name The name of the proxy service to create
 * @return struct proxy_service* Pointer to newly created proxy service, NULL if name is invalid
 *
 * This function:
 * 1. Allocates memory for a new proxy service structure
 * 2. Initializes all fields to NULL or 0
 * 3. Sets the proxy name to the provided name parameter
 *
 * Fields initialized include:
 * - Basic proxy settings (name, type, ports)
 * - HTTP/HTTPS specific settings (domains, auth)
 * - Group settings
 * - Plugin settings
 *
 * @note Uses assert() to verify memory allocations
 * @note Caller is responsible for freeing returned structure
 */
static struct proxy_service *new_proxy_service(const char *name)
{
	if (!name) {
		return NULL;
	}

	// Allocate and verify memory
	struct proxy_service *ps = calloc(1, sizeof(struct proxy_service));
	assert(ps);
	assert(c_conf);

	// Initialize required fields
	ps->proxy_name = strdup(name);
	assert(ps->proxy_name);

	// All other fields are already set to NULL/0 by calloc
	ps->ftp_cfg_proxy_name = NULL;
	ps->proxy_type = NULL;
	ps->local_port = 0;
	ps->remote_port = 0;
	ps->remote_data_port = 0;
	ps->use_compression = 0;
	ps->use_encryption = 0;

	ps->service_type = NO_XDPI;

	// HTTP/HTTPS specific fields
	ps->custom_domains = NULL;
	ps->subdomain = NULL;
	ps->locations = NULL;
	ps->host_header_rewrite = NULL;
	ps->http_user = NULL;
	ps->http_pwd = NULL;

	// Group settings
	ps->group = NULL;
	ps->group_key = NULL;

	// Plugin settings
	ps->plugin = NULL;
	ps->plugin_user = NULL;
	ps->plugin_pwd = NULL;
	ps->s_root_dir = NULL;

	ps->bind_addr	= NULL;

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

/**
 * @brief Validates proxy service configuration parameters
 *
 * @param ps Pointer to proxy service structure to validate
 * @return int Returns 1 if validation passes, 0 if validation fails
 *
 * Validates proxy configuration based on service type:
 * - Common checks: proxy name and type must exist
 * - Socks5: requires remote port
 * - TCP/UDP: requires local port and IP
 * - HTTP/HTTPS: requires local port, IP, and either custom domains or subdomain
 *
 * Error messages are logged for any validation failures.
 */
int validate_proxy(struct proxy_service *ps)
{
	// Validate basic requirements
	if (!ps || !ps->proxy_name || !ps->proxy_type) {
		return 0;
	}

	// Common validation for services needing local endpoints
	int needs_local_endpoint = (strcmp(ps->proxy_type, "tcp") == 0 ||
							  strcmp(ps->proxy_type, "udp") == 0 ||
							  strcmp(ps->proxy_type, "http") == 0 ||
							  strcmp(ps->proxy_type, "https") == 0);

	if (needs_local_endpoint && (ps->local_port == 0 || ps->local_ip == NULL)) {
		debug(LOG_ERR, "Proxy [%s] error: local_port or local_ip not found", 
			  ps->proxy_name);
		return 0;
	}

	// Type-specific validation
	if (strcmp(ps->proxy_type, "socks5") == 0) {
		if (ps->remote_port == 0) {
			debug(LOG_ERR, "Proxy [%s] error: remote_port not found", 
				  ps->proxy_name);
			return 0;
		}
	}
	else if (strcmp(ps->proxy_type, "iod") == 0) {
		if (ps->remote_port == 0 || ps->local_port == 0) {
			debug(LOG_ERR, "Proxy [%s] error: remote_port and local_port must be set for IOD proxy", ps->proxy_name);
			return 0;
		}
	}
	else if (strcmp(ps->proxy_type, "http") == 0 || strcmp(ps->proxy_type, "https") == 0) {
		// Validate domain configuration
		if (ps->custom_domains && ps->subdomain) {
			debug(LOG_ERR, "Proxy [%s] error: custom_domains and subdomain cannot be set simultaneously", 
				  ps->proxy_name);
			return 0;
		}
		if (!ps->custom_domains && !ps->subdomain) {
			debug(LOG_ERR, "Proxy [%s] error: either custom_domains or subdomain must be set", 
				  ps->proxy_name);
			return 0;
		}
	}
	else if (strcmp(ps->proxy_type, "tcp") != 0 && strcmp(ps->proxy_type, "udp") != 0) {
		debug(LOG_ERR, "Proxy [%s] error: invalid proxy_type", ps->proxy_name);
		return 0;
	}

	return 1;
}

/**
 * @brief Add a new system user and set their password
 *
 * @param username The username to create
 * @param password The password to set for the user
 * @return int Returns 0 on success, -1 on failure
 *
 * This function:
 * 1. Checks if the user already exists
 * 2. Creates a new user with home directory and bash shell
 * 3. Sets the user's password
 * 4. Adds the user to the sudo group
 *
 * @note Requires sudo privileges to execute commands
 * @warning Input parameters should be properly sanitized before calling
 */
static int add_user_and_set_password(const char *username, const char *password) 
{
	if (!username || !password) {
		debug(LOG_ERR, "Invalid username or password");
		return -1;
	}

	// Verify user doesn't exist
	if (getpwnam(username) != NULL) {
		debug(LOG_ERR, "User %s already exists", username);
		return -1;
	}

	char cmd[256];
	int ret;

	// Create commands
	const char *commands[] = {
		"sudo useradd -m -s /bin/bash %s",    // Create user
		"echo '%s:%s' | sudo chpasswd",       // Set password
		"sudo usermod -aG sudo %s"            // Add to sudo group
	};

	// Execute create user command
	snprintf(cmd, sizeof(cmd), commands[0], username);
	if ((ret = system(cmd)) != 0) {
		debug(LOG_ERR, "Failed to create user %s", username);
		return -1;
	}

	// Execute set password command
	snprintf(cmd, sizeof(cmd), commands[1], username, password);
	if ((ret = system(cmd)) != 0) {
		debug(LOG_ERR, "Failed to set password for user %s", username);
		return -1;
	}

	// Execute add to sudo group command
	snprintf(cmd, sizeof(cmd), commands[2], username);
	if ((ret = system(cmd)) != 0) {
		debug(LOG_ERR, "Failed to add user %s to sudo group", username);
		return -1;
	}

	debug(LOG_DEBUG, "User %s added successfully", username);
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

static enum xdpi_service_type convert_service_type(const char *value)
{
	if (strcmp(value, "ssh") == 0) {
		return SERVICE_SSH;
	}
	else if (strcmp(value, "rdp") == 0) {
		return SERVICE_RDP;
	}
	else if (strcmp(value, "vnc") == 0) {
		return SERVICE_VNC;
	}
	else if (strcmp(value, "telnet") == 0) {
		return SERVICE_TELNET;
	}
	else if (strcmp(value, "http") == 0) {
		return SERVICE_HTTP;
	}
	else if (strcmp(value, "https") == 0) {
		return SERVICE_HTTPS;
	}
	else if (strcmp(value, "mstsc") == 0) {
		return SERVICE_MSTSC;
	}
	
	return NO_XDPI;
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
	else if (MATCH_NAME("bind_addr")) SET_STRING_VALUE(bind_addr);
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
	else if (MATCH_NAME("service_type")) ps->service_type = convert_service_type(value);
	else if (MATCH_NAME("start_hour")) {
		int hour = atoi(value);
		if (hour < 0 || hour > 23) {
			debug(LOG_ERR, "Invalid start_hour value: %s", value);
			exit(0);
		}
		ps->start_hour = hour;
	}
	else if (MATCH_NAME("end_hour")) {
		int hour = atoi(value);
		if (hour < 0 || hour > 23) {
			debug(LOG_ERR, "Invalid end_hour value: %s", value);
			exit(0);
		}
		ps->end_hour = hour;
	}
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
