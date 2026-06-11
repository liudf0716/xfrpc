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
#include <ctype.h>
#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>

#include "ini.h"
#include "uthash.h"
#include "config.h"
#include "visitor.h"
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
	"tcpmux",
	"stcp",
	"xtcp",
	"sudp",
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
	if (!c_conf)
		return;
	SAFE_FREE(c_conf->server_addr);
	SAFE_FREE(c_conf->auth_token);
	SAFE_FREE(c_conf->tls_cert_file);
	SAFE_FREE(c_conf->tls_key_file);
	SAFE_FREE(c_conf->tls_trusted_ca_file);
	SAFE_FREE(c_conf->tls_server_name);
	SAFE_FREE(c_conf->user);
	SAFE_FREE(c_conf->protocol);
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

	debug(LOG_DEBUG, "Section[common]: {server_addr:%s, server_port:%d, auth_token:%s, interval:%d, timeout:%d, tls:%d}",
		c_conf->server_addr, 
		c_conf->server_port, 
		c_conf->auth_token, 
		c_conf->heartbeat_interval, 
		c_conf->heartbeat_timeout,
		c_conf->tls_enable);

	if (c_conf->tls_enable) {
		debug(LOG_DEBUG, "  TLS: {ca:%s, cert:%s, key:%s, server_name:%s}",
			c_conf->tls_trusted_ca_file ? c_conf->tls_trusted_ca_file : "(default)",
			c_conf->tls_cert_file ? c_conf->tls_cert_file : "(none)",
			c_conf->tls_key_file ? c_conf->tls_key_file : "(none)",
			c_conf->tls_server_name ? c_conf->tls_server_name : "(auto)");
	}
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

	// Log tcpmux-specific fields
	if (ps->proxy_type && strcmp(ps->proxy_type, "tcpmux") == 0) {
		debug(LOG_DEBUG,
			"  TCPMux: {multiplexer:%s, route_by_http_user:%s}",
			ps->multiplexer ? ps->multiplexer : "httpconnect (default)",
			ps->route_by_http_user ? ps->route_by_http_user : "(none)");
	}

	// Log stcp/xtcp/sudp-specific fields
	if (ps->proxy_type && (strcmp(ps->proxy_type, "stcp") == 0 ||
			strcmp(ps->proxy_type, "xtcp") == 0 ||
			strcmp(ps->proxy_type, "sudp") == 0)) {
		debug(LOG_DEBUG,
			"  STCP: {sk:%s, allow_users:%s}",
			ps->sk ? "****" : "(none)",
			ps->allow_users ? ps->allow_users : "(any)");
	}

	// Log health check configuration
	if (ps->health_check_type) {
		debug(LOG_DEBUG,
			"  HealthCheck: {type:%s, url:%s, interval:%ds, timeout:%ds, max_failed:%d}",
			ps->health_check_type,
			ps->health_check_url ? ps->health_check_url : "/",
			ps->health_check_interval,
			ps->health_check_timeout,
			ps->health_check_max_failed);
	}
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

	// Allocate and verify memory (calloc zeros all fields)
	struct proxy_service *ps = calloc(1, sizeof(struct proxy_service));
	assert(ps);
	assert(c_conf);

	// Initialize required fields
	ps->proxy_name = strdup(name);
	assert(ps->proxy_name);

	// Set non-zero defaults
	ps->service_type = NO_XDPI;
	ps->health_check_interval = 10;
	ps->health_check_timeout = 3;
	ps->health_check_max_failed = 1;

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
			exit(EXIT_FAILURE);
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
							  strcmp(ps->proxy_type, "https") == 0 ||
							  strcmp(ps->proxy_type, "tcpmux") == 0 ||
							  strcmp(ps->proxy_type, "stcp") == 0 ||
							  strcmp(ps->proxy_type, "xtcp") == 0 ||
							  strcmp(ps->proxy_type, "sudp") == 0);

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
	else if (strcmp(ps->proxy_type, "tcpmux") == 0) {
		// TCPMux requires domain configuration like http/https
		if (ps->custom_domains && ps->subdomain) {
			debug(LOG_ERR, "Proxy [%s] error: custom_domains and subdomain cannot be set simultaneously",
				  ps->proxy_name);
			return 0;
		}
		if (!ps->custom_domains && !ps->subdomain) {
			debug(LOG_ERR, "Proxy [%s] error: either custom_domains or subdomain must be set for tcpmux",
				  ps->proxy_name);
			return 0;
		}
	}
	else if (strcmp(ps->proxy_type, "stcp") == 0 ||
			 strcmp(ps->proxy_type, "xtcp") == 0 ||
			 strcmp(ps->proxy_type, "sudp") == 0) {
		// STCP/XTCP/SUDP require a secret key
		if (!ps->sk) {
			debug(LOG_ERR, "Proxy [%s] error: sk (secret_key) must be set for %s",
				  ps->proxy_name, ps->proxy_type);
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

	// Validate password: reject unsafe characters and enforce length limit
	size_t pwd_len = strlen(password);
	if (pwd_len > 128) {
		debug(LOG_ERR, "Password too long (max 128 characters)");
		return -1;
	}
	for (const char *p = password; *p; p++) {
		if (*p == '\n' || *p == '\r' || *p == ':' || *p == '\0') {
			debug(LOG_ERR, "Password contains unsafe characters");
			return -1;
		}
	}

	// Reject usernames or passwords containing shell-unsafe characters to
	// prevent command injection when they are embedded in shell commands.
	for (const char *p = username; *p; p++) {
		if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') {
			debug(LOG_ERR, "Username contains unsafe characters");
			return -1;
		}
	}

	// Verify user doesn't exist
	if (getpwnam(username) != NULL) {
		debug(LOG_ERR, "User %s already exists", username);
		return -1;
	}

	char cmd[256];
	int ret;

	/* On embedded systems (OpenWrt, etc.) the process typically runs as
	 * root directly and sudo is not installed.  Only prefix commands with
	 * "sudo" when we are *not* already root. */
	const char *sudo = (getuid() == 0) ? "" : "sudo ";

	// Create user
	snprintf(cmd, sizeof(cmd), "%suseradd -m -s /bin/bash %s", sudo, username);
	if ((ret = system(cmd)) != 0) {
		debug(LOG_ERR, "Failed to create user %s", username);
		return -1;
	}

	// Set password by piping "username:password\n" directly to chpasswd via
	// popen, avoiding any shell interpretation of the password string.
	char chpasswd_cmd[128];
	snprintf(chpasswd_cmd, sizeof(chpasswd_cmd), "%schpasswd", sudo);
	FILE *fp = popen(chpasswd_cmd, "w");
	if (!fp) {
		debug(LOG_ERR, "Failed to open chpasswd pipe for user %s", username);
		return -1;
	}
	fprintf(fp, "%s:%s\n", username, password);
	ret = pclose(fp);
	if (ret != 0) {
		debug(LOG_ERR, "Failed to set password for user %s", username);
		return -1;
	}

	// Add to sudo group (skip if already root — no group to add to)
	if (getuid() != 0) {
		snprintf(cmd, sizeof(cmd), "%susermod -aG sudo %s", sudo, username);
		if ((ret = system(cmd)) != 0) {
			debug(LOG_ERR, "Failed to add user %s to sudo group", username);
			return -1;
		}
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
	{"unix_domain_socket", 0, 0, "127.0.0.1"},
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
			if (strcmp(plugins[i].name, "unix_domain_socket") == 0) {
				/* UDS plugin: no local_port needed, uses plugin_unix_path */
				if (!ps->plugin_unix_path) {
					debug(LOG_ERR, "Plugin unix_domain_socket requires plugin_unix_path");
					exit(EXIT_FAILURE);
				}
			} else if (strcmp(plugins[i].name, "telnetd") == 0) {
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

	// Route visitor sections to visitor parser
	if (strstr(sect, "visitor") != NULL) {
		parse_visitor_section(sect, nm, value);
		return 0;
	}

	// Strip "proxy:" prefix if present (e.g., [proxy:stcp_ssh] -> stcp_ssh)
	const char *proxy_name = sect;
	if (strncmp(sect, "proxy:", 6) == 0) {
		proxy_name = sect + 6;
		if (*proxy_name == '\0') {
			debug(LOG_ERR, "Empty proxy name after 'proxy:' prefix");
			return 0;
		}
	}

	// Find or create proxy service
	struct proxy_service *ps = NULL;
	HASH_FIND_STR(all_ps, proxy_name, ps);
	if (!ps) {
		ps = new_proxy_service(proxy_name);
		if (!ps) {
			debug(LOG_ERR, "Failed to create proxy service");
			exit(EXIT_FAILURE);
		}
		HASH_ADD_KEYPTR(hh, all_ps, ps->proxy_name, strlen(ps->proxy_name), ps);
	}

	#define MATCH_NAME(s) strcmp(nm, s) == 0
	#define SET_STRING_VALUE(field) do { \
		SAFE_FREE(ps->field); \
		ps->field = strdup(value); \
		assert(ps->field); \
	} while(0)

	// Process configuration parameters
	if (MATCH_NAME("type")) {
		if (!get_valid_type(value)) {
			debug(LOG_ERR, "Unsupported proxy type: %s", value);
			exit(EXIT_FAILURE);
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
	else if (MATCH_NAME("plugin_unix_path")) SET_STRING_VALUE(plugin_unix_path);
	else if (MATCH_NAME("root_dir")) SET_STRING_VALUE(s_root_dir);
	else if (MATCH_NAME("multiplexer")) SET_STRING_VALUE(multiplexer);
	else if (MATCH_NAME("route_by_http_user")) SET_STRING_VALUE(route_by_http_user);
	else if (MATCH_NAME("sk")) SET_STRING_VALUE(sk);
	else if (MATCH_NAME("allow_users")) SET_STRING_VALUE(allow_users);
	else if (MATCH_NAME("service_type")) ps->service_type = convert_service_type(value);
	else if (MATCH_NAME("health_check_type")) SET_STRING_VALUE(health_check_type);
	else if (MATCH_NAME("health_check_url")) SET_STRING_VALUE(health_check_url);
	else if (MATCH_NAME("health_check_interval")) ps->health_check_interval = atoi(value);
	else if (MATCH_NAME("health_check_timeout")) ps->health_check_timeout = atoi(value);
	else if (MATCH_NAME("health_check_max_failed")) ps->health_check_max_failed = atoi(value);
	else if (MATCH_NAME("start_time")) {
		int hour = atoi(value);
		if (hour < 0 || hour > 23) {
			debug(LOG_ERR, "Invalid start_time value: %s", value);
			exit(EXIT_FAILURE);
		}
		ps->start_time = hour;
	}
	else if (MATCH_NAME("end_time")) {
		int hour = atoi(value);
		if (hour < 0 || hour > 23) {
			debug(LOG_ERR, "Invalid end_time value: %s", value);
			exit(EXIT_FAILURE);
		}
		ps->end_time = hour;
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
	else if (MATCH("common", "protocol")) {
		SAFE_FREE(config->protocol);
		config->protocol = strdup(value);
	}
	else if (MATCH("common", "quic_bind_port")) {
		config->quic_bind_port = atoi(value);
	}
	/* TLS settings */
	else if (MATCH("common", "tls_enable")) {
		config->tls_enable = !!atoi(value);
	}
	else if (MATCH("common", "tls_cert_file")) {
		SAFE_FREE(config->tls_cert_file);
		config->tls_cert_file = strdup(value);
	}
	else if (MATCH("common", "tls_key_file")) {
		SAFE_FREE(config->tls_key_file);
		config->tls_key_file = strdup(value);
	}
	else if (MATCH("common", "tls_trusted_ca_file")) {
		SAFE_FREE(config->tls_trusted_ca_file);
		config->tls_trusted_ca_file = strdup(value);
	}
	else if (MATCH("common", "tls_server_name")) {
		SAFE_FREE(config->tls_server_name);
		config->tls_server_name = strdup(value);
	}
	else if (MATCH("common", "user")) {
		SAFE_FREE(config->user);
		config->user = strdup(value);
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
	config->tls_enable = 0;
	config->protocol = strdup("tcp");
	config->quic_bind_port = 0;
	config->tls_cert_file = NULL;
	config->tls_key_file = NULL;
	config->tls_trusted_ca_file = NULL;
	config->tls_server_name = NULL;
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
		exit(EXIT_FAILURE);
	}

	if (c_conf->heartbeat_timeout < c_conf->heartbeat_interval) {
		debug(LOG_ERR, "Error: heartbeat_timeout must be greater than heartbeat_interval");
		exit(EXIT_FAILURE);
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
		exit(EXIT_FAILURE);
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

/**
 * @brief Frees memory used by a proxy_service structure
 *
 * Deallocates memory for dynamically allocated strings within the proxy_service
 * structure and the structure itself.
 *
 * @param ps Pointer to the proxy_service structure to free
 */
void free_proxy_service(struct proxy_service *ps)
{
	if (!ps) {
		return;
	}

	SAFE_FREE(ps->proxy_name);
	SAFE_FREE(ps->ftp_cfg_proxy_name);
	SAFE_FREE(ps->proxy_type);
	SAFE_FREE(ps->local_ip);
	SAFE_FREE(ps->custom_domains);
	SAFE_FREE(ps->subdomain);
	SAFE_FREE(ps->locations);
	SAFE_FREE(ps->host_header_rewrite);
	SAFE_FREE(ps->http_user);
	SAFE_FREE(ps->http_pwd);
	SAFE_FREE(ps->group);
	SAFE_FREE(ps->group_key);
	SAFE_FREE(ps->plugin);
	SAFE_FREE(ps->plugin_user);
	SAFE_FREE(ps->plugin_pwd);
	SAFE_FREE(ps->plugin_unix_path);
	SAFE_FREE(ps->s_root_dir);
	SAFE_FREE(ps->bind_addr);
	SAFE_FREE(ps->multiplexer);
	SAFE_FREE(ps->route_by_http_user);
	SAFE_FREE(ps->sk);
	SAFE_FREE(ps->allow_users);
	SAFE_FREE(ps->health_check_type);
	SAFE_FREE(ps->health_check_url);
	SAFE_FREE(ps);
}

/**
 * @brief Frees all proxy_service structures from the all_ps hash table.
 *
 * Iterates through the all_ps hash table, removes each element,
 * and frees the associated proxy_service structure using free_proxy_service.
 * Finally, sets all_ps to NULL.
 */
void free_all_proxy_services(void)
{
	struct proxy_service *current_ps, *tmp;

	HASH_ITER(hh, all_ps, current_ps, tmp) {
		HASH_DEL(all_ps, current_ps);  /* delete it (all_ps advances to next) */
		free_proxy_service(current_ps); /* free it */
	}
	all_ps = NULL; /* Ensure the hash table head is NULL after clearing */
}
