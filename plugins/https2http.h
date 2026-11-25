// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * https2http plugin support for xfrpc
 */

#ifndef XFRPC_PLUGINS_HTTPS2HTTP_H
#define XFRPC_PLUGINS_HTTPS2HTTP_H

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <openssl/ssl.h>

struct proxy_client;
struct proxy_service;

/* Initialize and free per-service SSL context at config/startup time */
int https2http_init_service(struct proxy_service *ps);
void https2http_free_service(struct proxy_service *ps);

/* Initialize and setup https2http bridge for client */
int https2http_setup(struct proxy_client *client);

/* Callback when decrypted plaintext HTTP is read from ssl_bev */
void https2http_ssl_read_cb(struct bufferevent *bev, void *ctx);

/* Callback when plain HTTP response is read from local backend */
void https2http_local_read_cb(struct bufferevent *bev, void *ctx);

/* Event callback on ssl_bev */
void https2http_ssl_event_cb(struct bufferevent *bev, short what, void *ctx);

/* Callback when encrypted TLS response is read from bridge_bev (to forward to ctl/mux) */
void https2http_bridge_read_cb(struct bufferevent *bev, void *ctx);

/* Write callback on bridge_bev to complete deferred shutdown */
void https2http_bridge_write_cb(struct bufferevent *bev, void *ctx);

/* Drain encrypted data from bridge_bev to ctl/mux. Returns 0 on success, 1 on window stall, <0 on write error */
int https2http_bridge_drain(struct proxy_client *client);

/* Trigger TLS shutdown when local HTTP is done and all plaintext is submitted to ssl_bev */
void https2http_trigger_shutdown(struct proxy_client *client);

/* Finish closing the stream once bridge_bev has received EOF from ssl_bev and drained */
int https2http_try_finish_close(struct proxy_client *client);

/* Free resources allocated for https2http */
void https2http_client_cleanup(struct proxy_client *client);

#endif /* XFRPC_PLUGINS_HTTPS2HTTP_H */
