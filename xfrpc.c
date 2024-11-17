
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <errno.h>

#include <syslog.h>

#include <event2/event.h>

#include "commandline.h"
#include "client.h"
#include "config.h"
#include "uthash.h"
#include "control.h"
#include "debug.h"
#include "xfrpc.h"
#include "crypto.h"
#include "msg.h"
#include "utils.h"
#include "tcp_redir.h"
#include "config.h"

#include "plugins/youtubedl.h"
#include "plugins/telnetd.h"
#include "plugins/instaloader.h"
#include "plugins/httpd.h"

/**
 * @brief Starts local services based on proxy service configurations
 * 
 * Iterates through all configured proxy services and starts the corresponding
 * local services based on their plugin types:
 * - telnetd: Starts a simple telnet daemon
 * - instaloader: Starts Instagram downloader service
 * - youtubedl: Starts YouTube downloader service
 * - instaloader_redir: Starts TCP redirection service
 * - httpd: Starts HTTP daemon service
 */
static void start_xfrpc_local_service(void)
{
	struct proxy_service *ps, *ps_tmp;
	struct proxy_service *all_ps = get_all_proxy_services();

	HASH_ITER(hh, all_ps, ps, ps_tmp) {
		if (!ps->plugin)
			continue;

		if (strcmp(ps->plugin, "telnetd") == 0) {
			simple_telnetd_start(ps->local_port);
		} else if (strcmp(ps->plugin, "instaloader") == 0) {
			start_instaloader_service(ps->local_port);
		} else if (strcmp(ps->plugin, "youtubedl") == 0) {
			start_youtubedl_service(ps->local_port);
		} else if (strcmp(ps->plugin, "instaloader_redir") == 0) {
			start_tcp_redir_service(ps);
		} else if (strcmp(ps->plugin, "httpd") == 0) {
			start_httpd_service(ps);
		} else {
			debug(LOG_ERR, "start_xfrpc_local_service: unknown plugin %s", ps->plugin);
		}
	}
}

/**
 * @brief Main event loop for xfrpc
 * 
 * Initializes and runs the main control loop:
 * 1. Starts all configured local services
 * 2. Initializes main control
 * 3. Runs the control loop
 * 4. Cleans up on exit
 */
void xfrpc_loop(void)
{
	start_xfrpc_local_service();
	init_main_control();
	run_control();
	close_main_control();
}
