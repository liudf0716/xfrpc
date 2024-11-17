
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
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
#include "version.h"
#include "login.h"
#include "utils.h"

static struct login 		*c_login;

char *get_run_id()
{
	return c_login->run_id;
}

struct login *get_common_login_config()
{
	return c_login;
}

int is_logged()
{
	return c_login->logged;
}

/**
 * @brief Initializes the login structure with system and network information
 *
 * This function performs the following initialization steps:
 * 1. Allocates memory for the login structure if not already allocated
 * 2. Gets system information using uname()
 * 3. Sets basic version, OS and architecture information
 * 4. Initializes other login fields with default values
 * 5. Determines if device is a router based on network interface name
 * 6. Gets MAC address to use as run_id
 *
 * The function will exit with status 1 if any of the following errors occur:
 * - Memory allocation failure
 * - Failure to get common config
 * - Failure to get system information
 * - Failure to get network interface name
 * - Failure to get MAC address
 *
 * @note Global variables used:
 *       - c_login: Global login structure
 *       - PROTOCOL_VERSION: Protocol version string
 */
void init_login()
{
	// Initialize login structure
	if (!c_login) {
		c_login = calloc(sizeof(struct login), 1);
		if (!c_login) {
			debug(LOG_ERR, "Failed to allocate memory for login structure");
			exit(1);
		}
	}

	struct common_conf *c_conf = get_common_config();
	if (!c_conf) {
		debug(LOG_ERR, "Failed to get common config");
		exit(1);
	}

	// Get system information
	struct utsname uname_buf;
	if (uname(&uname_buf) != 0) {
		debug(LOG_ERR, "Failed to get system information");
		exit(1);
	}

	// Initialize basic fields
	c_login->version = strdup(PROTOCOL_VERESION);
	c_login->os = strdup(uname_buf.sysname);
	c_login->arch = strdup(uname_buf.machine);

	if (!c_login->version || !c_login->os || !c_login->arch) {
		debug(LOG_ERR, "Failed to allocate memory for login fields");
		exit(1);
	}

	// Initialize other fields with default values
	c_login->hostname = NULL;
	c_login->user = NULL;
	c_login->timestamp = 0;
	c_login->metas = NULL;
	c_login->pool_count = 1;
	c_login->privilege_key = NULL;
	c_login->logged = 0;

	// Get network interface information
	char ifname[16] = {0};
	if (get_net_ifname(ifname, sizeof(ifname)) != 0) {
		debug(LOG_ERR, "Failed to get network interface name");
		exit(1);
	}

	// Check if device is a router
	if (strcmp(ifname, "br-lan") == 0 || strcmp(ifname, "br0") == 0) {
		c_conf->is_router = 1;
		debug(LOG_DEBUG, "Device identified as router");
	}

	// Get MAC address
	char if_mac[64] = {0};
	if (get_net_mac(ifname, if_mac, sizeof(if_mac)) != 0) {
		debug(LOG_ERR, "Failed to get MAC address for interface %s", ifname);
		exit(1);
	}

	c_login->run_id = strdup(if_mac);
	if (!c_login->run_id) {
		debug(LOG_ERR, "Failed to allocate memory for run_id");
		exit(1);
	}
}

/**
 * @brief Validates and processes the login response from the server
 *
 * This function checks if the login response is valid by verifying the run_id.
 * If valid, it updates the client's run_id and sets the logged status.
 * If invalid, it logs error messages and sets logged status to 0.
 *
 * @param lr Pointer to the login_resp structure containing server response
 *
 * @return 1 if login response is valid and processing successful
 * @return 0 if login response is invalid or processing failed
 *
 * @note The function will free existing run_id before updating with new value
 */
int login_resp_check(struct login_resp *lr)
{
	// Check for invalid run_id
	if (!lr->run_id || strlen(lr->run_id) <= 1) {
		// Log error message if available
		if (lr->error && *lr->error) {
			debug(LOG_ERR, "login response error: %s", lr->error);
		}
		debug(LOG_ERR, "login failed!");
		c_login->logged = 0;
		return 0;
	}

	// Login successful
	debug(LOG_DEBUG, "xfrp login response: run_id: [%s], version: [%s]", 
		  lr->run_id, lr->version);

	// Update run_id
	SAFE_FREE(c_login->run_id);
	c_login->run_id = strdup(lr->run_id);
	assert(c_login->run_id);

	c_login->logged = 1;
	return 1;
}
