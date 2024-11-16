/*
 * Copyright (C) 2016-2024 Dengfeng Liu <liu_df@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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

void init_login()
{
	if (! c_login) 
		c_login = calloc(sizeof(struct login), 1);

	assert(c_login);

	struct common_conf *c_conf = get_common_config();
	assert(c_conf);

	struct utsname uname_buf;
	if (uname(&uname_buf)) {
		debug(LOG_ERR, "error: get system info failed!");
		exit(0);
	}

	c_login->version 		= strdup(PROTOCOL_VERESION);
	assert(c_login->version);
	c_login->hostname 		= NULL;
	c_login->os 			= strdup(uname_buf.sysname);
	assert(c_login->os);
	c_login->arch 			= strdup(uname_buf.machine);
	assert(c_login->arch);
	c_login->user 			= NULL;

	c_login->timestamp 		= 0;
	c_login->run_id 		= NULL;
	c_login->metas			= NULL;
	c_login->pool_count 	= 1;
	c_login->privilege_key 	= NULL;

	c_login->logged 		= 0;

	/* start to init login->run_id */
	char ifname[16] = {0};
	if(get_net_ifname(ifname, 16)){
		debug(LOG_ERR, "error: get device sign ifname failed!");
		exit(0);
	}

	if (strcmp(ifname, "br-lan") == 0 || strcmp(ifname, "br0") == 0) {
		c_conf->is_router = 1;
		debug(LOG_DEBUG, "working in router");
	}

	char if_mac[64] = {0};
	if(get_net_mac(ifname, if_mac, sizeof(if_mac))) {
		debug(LOG_ERR, "error: Hard ware MAC address of [%s] get failed!", ifname);
		exit(0);
	}

	c_login->run_id = strdup(if_mac);
	assert(c_login->run_id);
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
