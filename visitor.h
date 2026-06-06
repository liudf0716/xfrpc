// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_VISITOR_H
#define XFRPC_VISITOR_H

#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/event.h>

#include "client.h"
#include "tcpmux.h"

/* Visitor configuration parsed from INI sections like [stcp_visitor:name] */
struct visitor_conf {
	char    *visitor_name;       /* Section name suffix, e.g. "ssh" */
	char    *visitor_type;       /* "stcp", "xtcp", "sudp" */
	char    *server_name;        /* Remote proxy name to connect to */
	char    *secret_key;         /* Shared secret for authentication */
	char    *bind_addr;          /* Local listen address (default 127.0.0.1) */
	int      bind_port;          /* Local listen port */
	int      use_encryption;
	int      use_compression;

	/* Hash handling */
	UT_hash_handle hh;
};

/* Runtime visitor instance */
struct visitor_instance {
	struct visitor_conf         *conf;
	struct event_base           *base;
	struct evconnlistener       *listener;
	struct bufferevent          *ctl_bev;    /* Connection to frps */
	struct tmux_stream           stream;

	/* Hash handling */
	UT_hash_handle               hh;
};

/**
 * @brief Initialize all configured visitors.
 *
 * Called after login succeeds. For each visitor_conf in the config,
 * connects to frps, sends NewVisitorConn, and starts a local listener.
 */
void init_visitors(struct event_base *base);

/**
 * @brief Free all visitor configurations.
 */
void free_all_visitor_confs(void);

/**
 * @brief Stop and free all running visitor instances.
 *
 * Closes all listener sockets and frees visitor_instance structures.
 * Call this before reloading configuration.
 */
void free_all_visitor_instances(void);

/**
 * @brief Get all visitor configurations.
 */
struct visitor_conf *get_all_visitor_confs(void);

/**
 * @brief Handle NewVisitorConnResp from frps.
 *
 * Called from control.c when TypeNewVisitorConnResp is received.
 */
void handle_visitor_conn_resp(const char *resp_json, struct bufferevent *bev);

#endif // XFRPC_VISITOR_H
