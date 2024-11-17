
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>


#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"
#include "config.h"

/**
 * @brief Creates a new proxy object
 * 
 * Allocates memory for a new proxy structure and initializes its members.
 * The proxy object is used to manage proxy connections and their properties.
 *
 * @param bev Bufferevent associated with the proxy connection
 * @return struct proxy* Pointer to newly created proxy object, NULL if allocation fails
 */
struct proxy *
new_proxy_obj(struct bufferevent *bev)
{
	struct proxy *proxy = (struct proxy *)calloc(1, sizeof(struct proxy));
	if (!proxy) {
		return NULL;
	}
	
	proxy->bev = bev;
	proxy->remote_data_port = -1;
	proxy->proxy_name = NULL;
	
	return proxy;
}

/**
 * @brief Frees a proxy object and its resources
 * 
 * Deallocates memory used by the proxy structure and its members.
 * Should be called when the proxy connection is no longer needed.
 *
 * @param proxy Pointer to the proxy object to be freed
 */
void 
free_proxy_obj(struct proxy *proxy)
{
	if (proxy) {
		SAFE_FREE(proxy->proxy_name);
		SAFE_FREE(proxy);
	}
}
