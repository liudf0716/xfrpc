// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_TLS_H
#define XFRPC_TLS_H

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/**
 * Initialize the global TLS/SSL context using configuration from common_conf.
 * Must be called once before any TLS connections are made.
 *
 * @return 0 on success, -1 on failure
 */
int tls_init(void);

/**
 * Wrap an existing TCP bufferevent with TLS.
 * The original bev is consumed; returns a new SSL-wrapped bev on success,
 * or NULL on failure (original bev is freed on failure).
 *
 * @param base   Event base for the new bufferevent
 * @param bev    The raw TCP bufferevent to wrap (consumed on success)
 * @return       TLS-wrapped bufferevent, or NULL on error
 */
struct bufferevent *tls_wrap_bev(struct event_base *base, struct bufferevent *bev);

/**
 * Clean up and free the global TLS context.
 * Call during shutdown.
 */
void tls_cleanup(void);

/**
 * Check if TLS is enabled in configuration.
 *
 * @return 1 if TLS is enabled, 0 otherwise
 */
int tls_is_enabled(void);

/**
 * Print OpenSSL error details to debug log.
 *
 * @param context  Description string for the error context
 */
void tls_log_errors(const char *context);

#endif /* XFRPC_TLS_H */
