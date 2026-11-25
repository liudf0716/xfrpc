// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Standard frpc client plugins: http_proxy, static_file
 */

#ifndef XFRPC_PLUGINS_STD_PLUGINS_H
#define XFRPC_PLUGINS_STD_PLUGINS_H

struct proxy_client;
struct proxy_service;

int is_std_plugin_proxy(const struct proxy_service *ps);
int std_plugin_setup(struct proxy_client *client);
void std_plugin_cleanup(struct proxy_client *client);

#endif /* XFRPC_PLUGINS_STD_PLUGINS_H */
