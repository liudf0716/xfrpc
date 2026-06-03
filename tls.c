// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * TLS/SSL support for xfrpc using OpenSSL + libevent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <event2/bufferevent_ssl.h>

#include "tls.h"
#include "config.h"
#include "debug.h"

/* Global SSL context */
static SSL_CTX *g_ssl_ctx = NULL;

/**
 * Print accumulated OpenSSL error stack to debug log.
 */
void tls_log_errors(const char *context)
{
	unsigned long err;
	while ((err = ERR_get_error()) != 0) {
		char buf[256];
		ERR_error_string_n(err, buf, sizeof(buf));
		debug(LOG_ERR, "[TLS] %s: %s", context, buf);
	}
}

/**
 * Check if TLS is enabled in the current configuration.
 */
int tls_is_enabled(void)
{
	struct common_conf *conf = get_common_config();
	return (conf && conf->tls_enable);
}

/**
 * Verify callback for SSL certificate chain.
 * Returns 1 to accept, 0 to reject.
 */
static int tls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	if (!preverify_ok) {
		int err = X509_STORE_CTX_get_error(ctx);
		int depth = X509_STORE_CTX_get_error_depth(ctx);
		debug(LOG_ERR, "[TLS] Certificate verification failed at depth %d: %s",
			  depth, X509_verify_cert_error_string(err));
	}
	return preverify_ok;
}

/**
 * Initialize the global SSL_CTX from common_conf settings.
 *
 * @return 0 on success, -1 on failure
 */
int tls_init(void)
{
	struct common_conf *conf = get_common_config();
	if (!conf || !conf->tls_enable) {
		debug(LOG_DEBUG, "[TLS] TLS is disabled");
		return 0;
	}

	/* Create TLS 1.2+ client context */
	g_ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (!g_ssl_ctx) {
		tls_log_errors("SSL_CTX_new");
		return -1;
	}

	/* Set minimum TLS version to 1.2 */
	SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);

	/* Load trusted CA certificate for server verification */
	if (conf->tls_trusted_ca_file) {
		if (SSL_CTX_load_verify_locations(g_ssl_ctx, conf->tls_trusted_ca_file, NULL) != 1) {
			debug(LOG_ERR, "[TLS] Failed to load CA file: %s", conf->tls_trusted_ca_file);
			tls_log_errors("SSL_CTX_load_verify_locations");
			SSL_CTX_free(g_ssl_ctx);
			g_ssl_ctx = NULL;
			return -1;
		}
		/* Enable certificate verification */
		SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, tls_verify_callback);
		debug(LOG_DEBUG, "[TLS] CA file loaded: %s", conf->tls_trusted_ca_file);
	} else {
		/* No CA file: still verify peer but use system defaults */
		SSL_CTX_set_default_verify_paths(g_ssl_ctx);
		SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, tls_verify_callback);
		debug(LOG_DEBUG, "[TLS] Using system default CA store");
	}

	/* Load client certificate + key (optional, for mutual TLS) */
	if (conf->tls_cert_file) {
		if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx, conf->tls_cert_file) != 1) {
			debug(LOG_ERR, "[TLS] Failed to load client cert: %s", conf->tls_cert_file);
			tls_log_errors("SSL_CTX_use_certificate_chain_file");
			SSL_CTX_free(g_ssl_ctx);
			g_ssl_ctx = NULL;
			return -1;
		}
		debug(LOG_DEBUG, "[TLS] Client certificate loaded: %s", conf->tls_cert_file);
	}

	if (conf->tls_key_file) {
		if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, conf->tls_key_file, SSL_FILETYPE_PEM) != 1) {
			debug(LOG_ERR, "[TLS] Failed to load private key: %s", conf->tls_key_file);
			tls_log_errors("SSL_CTX_use_PrivateKey_file");
			SSL_CTX_free(g_ssl_ctx);
			g_ssl_ctx = NULL;
			return -1;
		}

		/* Verify private key matches certificate */
		if (conf->tls_cert_file && SSL_CTX_check_private_key(g_ssl_ctx) != 1) {
			debug(LOG_ERR, "[TLS] Private key does not match certificate");
			tls_log_errors("SSL_CTX_check_private_key");
			SSL_CTX_free(g_ssl_ctx);
			g_ssl_ctx = NULL;
			return -1;
		}
		debug(LOG_DEBUG, "[TLS] Private key loaded: %s", conf->tls_key_file);
	}

	debug(LOG_INFO, "[TLS] SSL context initialized (TLS 1.2+)");
	return 0;
}

/**
 * Wrap a raw TCP bufferevent with TLS.
 *
 * Creates an SSL object, sets SNI hostname, and wraps the socket fd
 * in a new bufferevent_ssl.  The original bev is consumed.
 *
 * @param base  Event base
 * @param bev   Raw TCP bufferevent (consumed)
 * @return      TLS-wrapped bufferevent, or NULL on error
 */
struct bufferevent *tls_wrap_bev(struct event_base *base, struct bufferevent *bev)
{
	if (!g_ssl_ctx) {
		debug(LOG_ERR, "[TLS] SSL context not initialized");
		return NULL;
	}

	if (!bev) {
		debug(LOG_ERR, "[TLS] NULL bufferevent to wrap");
		return NULL;
	}

	/* Get the raw fd before freeing the plain bev */
	evutil_socket_t fd = bufferevent_getfd(bev);
	if (fd < 0) {
		debug(LOG_ERR, "[TLS] Cannot get fd from bufferevent");
		return NULL;
	}

	/* Detach fd from the plain bev so it survives bev_free */
	debug(LOG_DEBUG, "[TLS] Wrapping fd %d with TLS", (int)fd);
	bufferevent_setfd(bev, -1);
	bufferevent_free(bev);

	/* Create SSL object */
	SSL *ssl = SSL_new(g_ssl_ctx);
	if (!ssl) {
		tls_log_errors("SSL_new");
		evutil_closesocket(fd);
		return NULL;
	}

	/* Set SNI hostname for server certificate verification */
	struct common_conf *conf = get_common_config();
	const char *sni_host = conf->tls_server_name ? conf->tls_server_name : conf->server_addr;
	if (sni_host && !conf->tls_server_name) {
		/* Only set SNI for hostname (not raw IP) */
		struct in_addr addr;
		if (inet_pton(AF_INET, sni_host, &addr) != 1) {
			/* Not an IP, treat as hostname */
			SSL_set_tlsext_host_name(ssl, sni_host);
			debug(LOG_DEBUG, "[TLS] SNI set to: %s", sni_host);
		}
	} else if (conf->tls_server_name) {
		SSL_set_tlsext_host_name(ssl, conf->tls_server_name);
		debug(LOG_DEBUG, "[TLS] SNI set to: %s", conf->tls_server_name);
	}

	/* Set hostname for verification (skip for raw IP addresses) */
	SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	if (sni_host) {
		struct in_addr addr4;
		struct in6_addr addr6;
		int is_ip = (inet_pton(AF_INET, sni_host, &addr4) == 1 ||
					inet_pton(AF_INET6, sni_host, &addr6) == 1);
		if (!is_ip) {
			SSL_set1_host(ssl, sni_host);
		} else {
			debug(LOG_DEBUG, "[TLS] Skipping hostname verification for IP address: %s", sni_host);
		}
	}

	/* Create SSL-wrapped bufferevent */
	int sock_err = 0;
	socklen_t err_len = sizeof(sock_err);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
	debug(LOG_DEBUG, "tls_wrap_bev: fd=%d, sock_error=%d (%s)", (int)fd, sock_err, strerror(sock_err));
	struct bufferevent *ssl_bev = bufferevent_openssl_socket_new(
		base, fd, ssl,
		BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS
	);

	if (!ssl_bev) {
		tls_log_errors("bufferevent_openssl_socket_new");
		SSL_free(ssl);
		evutil_closesocket(fd);
		return NULL;
	}

	/* Allow dirty shutdown to avoid log noise on reconnect */
	bufferevent_openssl_set_allow_dirty_shutdown(ssl_bev, 1);

	debug(LOG_INFO, "[TLS] Connection wrapped with TLS");
	return ssl_bev;
}

/**
 * Clean up the global SSL context.
 */
void tls_cleanup(void)
{
	if (g_ssl_ctx) {
		SSL_CTX_free(g_ssl_ctx);
		g_ssl_ctx = NULL;
		debug(LOG_DEBUG, "[TLS] SSL context freed");
	}
}
