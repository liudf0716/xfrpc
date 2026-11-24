// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * https2http plugin support for xfrpc
 * Terminates HTTPS/TLS on client and forwards plain HTTP to local service.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "https2http.h"
#include "../client.h"
#include "../config.h"
#include "../control.h"
#include "../debug.h"
#include "../tcpmux.h"
#include "../proxy.h"

static SSL_CTX *g_https2http_ctx = NULL;

static int generate_self_signed_cert(SSL_CTX *ctx)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!pctx) return -1;
	if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return -1; }
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) { EVP_PKEY_CTX_free(pctx); return -1; }
	if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return -1; }
	EVP_PKEY_CTX_free(pctx);

	X509 *x509 = X509_new();
	if (!x509) { EVP_PKEY_free(pkey); return -1; }

	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 315360000L); /* 10 years */
	X509_set_pubkey(x509, pkey);

	X509_NAME *name = X509_get_subject_name(x509);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"xfrpc-https2http", -1, -1, 0);
	X509_set_issuer_name(x509, name);

	X509_sign(x509, pkey, EVP_sha256());

	int ret1 = SSL_CTX_use_certificate(ctx, x509);
	int ret2 = SSL_CTX_use_PrivateKey(ctx, pkey);

	X509_free(x509);
	EVP_PKEY_free(pkey);

	return (ret1 > 0 && ret2 > 0) ? 0 : -1;
}

static SSL_CTX *get_or_init_ssl_ctx(struct proxy_service *ps)
{
	if (g_https2http_ctx) {
		return g_https2http_ctx;
	}

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		debug(LOG_ERR, "https2http: Failed to create SSL_CTX");
		return NULL;
	}

	if (ps->plugin_crt_path && ps->plugin_key_path) {
		if (SSL_CTX_use_certificate_file(ctx, ps->plugin_crt_path, SSL_FILETYPE_PEM) <= 0 ||
		    SSL_CTX_use_PrivateKey_file(ctx, ps->plugin_key_path, SSL_FILETYPE_PEM) <= 0) {
			debug(LOG_ERR, "https2http: Failed to load cert [%s] or key [%s], generating self-signed cert",
			      ps->plugin_crt_path, ps->plugin_key_path);
			if (generate_self_signed_cert(ctx) < 0) {
				debug(LOG_ERR, "https2http: Failed to generate fallback self-signed cert");
				SSL_CTX_free(ctx);
				return NULL;
			}
		} else {
			debug(LOG_INFO, "https2http: Successfully loaded cert [%s] and key [%s]",
			      ps->plugin_crt_path, ps->plugin_key_path);
		}
	} else {
		debug(LOG_INFO, "https2http: No cert/key provided, generating self-signed certificate");
		if (generate_self_signed_cert(ctx) < 0) {
			debug(LOG_ERR, "https2http: Failed to generate self-signed cert");
			SSL_CTX_free(ctx);
			return NULL;
		}
	}

	g_https2http_ctx = ctx;
	return g_https2http_ctx;
}

void https2http_client_cleanup(struct proxy_client *client)
{
	if (!client) return;

	if (client->ssl_bev) {
		bufferevent_free(client->ssl_bev);
		client->ssl_bev = NULL;
	}
	if (client->bridge_bev) {
		bufferevent_free(client->bridge_bev);
		client->bridge_bev = NULL;
	}
	if (client->bridge_fd >= 0) {
		close(client->bridge_fd);
		client->bridge_fd = -1;
	}
}

static char *rewrite_http_host(const char *req, size_t req_len, const char *new_host, size_t *out_len)
{
	const char *hdr_end = strstr(req, "\r\n\r\n");
	if (!hdr_end) {
		return NULL;
	}
	size_t hdr_len = (hdr_end - req) + 4;

	char *buf = malloc(req_len + strlen(new_host) + 128);
	if (!buf) return NULL;

	char *out = buf;
	const char *p = req;
	int host_replaced = 0;

	while (p < hdr_end) {
		const char *line_end = strstr(p, "\r\n");
		if (!line_end || line_end > hdr_end) break;

		if (strncasecmp(p, "Host:", 5) == 0) {
			out += sprintf(out, "Host: %s\r\n", new_host);
			host_replaced = 1;
		} else {
			size_t line_len = (line_end - p) + 2;
			memcpy(out, p, line_len);
			out += line_len;
		}
		p = line_end + 2;
	}

	if (!host_replaced && new_host && *new_host) {
		out += sprintf(out, "Host: %s\r\n", new_host);
	}

	memcpy(out, "\r\n", 2);
	out += 2;

	size_t body_len = req_len - hdr_len;
	if (body_len > 0) {
		memcpy(out, hdr_end + 4, body_len);
		out += body_len;
	}

	*out_len = out - buf;
	return buf;
}

void https2http_ssl_read_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	if (!client || !client->local_proxy_bev) return;

	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	if (len == 0) return;

	const char *new_host = client->ps->plugin_host_header_rewrite ?
	                       client->ps->plugin_host_header_rewrite : client->ps->host_header_rewrite;

	if (!client->header_rewritten && new_host && *new_host) {
		char *raw = malloc(len + 1);
		if (!raw) return;
		evbuffer_copyout(src, raw, len);
		raw[len] = '\0';

		size_t rewritten_len = 0;
		char *rewritten = rewrite_http_host(raw, len, new_host, &rewritten_len);
		free(raw);

		if (rewritten) {
			evbuffer_drain(src, len);
			bufferevent_write(client->local_proxy_bev, rewritten, rewritten_len);
			free(rewritten);
			client->header_rewritten = 1;
			debug(LOG_DEBUG, "https2http: HTTP Host rewritten to [%s]", new_host);
			return;
		}
	}

	struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
	evbuffer_add_buffer(dst, src);
}

void https2http_local_read_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	if (!client || !client->ssl_bev) return;

	struct evbuffer *src = bufferevent_get_input(bev);
	struct evbuffer *dst = bufferevent_get_output(client->ssl_bev);
	evbuffer_add_buffer(dst, src);
}

void https2http_ssl_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	if (!client) return;

	if (what & BEV_EVENT_CONNECTED) {
		debug(LOG_DEBUG, "https2http: TLS handshake accepted for client stream %u", client->stream_id);
	} else if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		debug(LOG_DEBUG, "https2http: TLS session closed (what=0x%x)", what);
		if (client->local_proxy_bev) {
			bufferevent_free(client->local_proxy_bev);
			client->local_proxy_bev = NULL;
		}
		del_proxy_client_by_stream_id(client->stream_id);
	}
}

void https2http_bridge_read_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	if (!client || !client->ctl_bev) return;

	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	if (len == 0) return;

	struct common_conf *c_conf = get_common_config();
	if (!c_conf->tcp_mux) {
		struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
		evbuffer_add_buffer(dst, src);
		return;
	}

	while (evbuffer_get_length(src) > 0) {
		int written = tmux_stream_write(client->ctl_bev, src, &client->stream);
		if (written <= 0) {
			break;
		}
	}
}

int https2http_setup(struct proxy_client *client)
{
	if (!client || !client->ps || !client->base) return -1;

	SSL_CTX *ctx = get_or_init_ssl_ctx(client->ps);
	if (!ctx) return -1;

	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp) < 0) {
		debug(LOG_ERR, "https2http: socketpair failed: %s", strerror(errno));
		return -1;
	}

	SSL *ssl = SSL_new(ctx);
	if (!ssl) {
		close(sp[0]);
		close(sp[1]);
		return -1;
	}

	client->ssl_bev = bufferevent_openssl_socket_new(
		client->base, sp[0], ssl,
		BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS
	);
	if (!client->ssl_bev) {
		SSL_free(ssl);
		close(sp[0]);
		close(sp[1]);
		return -1;
	}

	bufferevent_openssl_set_allow_dirty_shutdown(client->ssl_bev, 1);
	bufferevent_setcb(client->ssl_bev, https2http_ssl_read_cb, NULL, https2http_ssl_event_cb, client);
	bufferevent_enable(client->ssl_bev, EV_READ | EV_WRITE);

	client->bridge_fd = sp[1];
	client->bridge_bev = bufferevent_socket_new(client->base, sp[1], BEV_OPT_CLOSE_ON_FREE);
	if (client->bridge_bev) {
		bufferevent_setcb(client->bridge_bev, https2http_bridge_read_cb, NULL, NULL, client);
		bufferevent_enable(client->bridge_bev, EV_READ | EV_WRITE);
	}

	client->header_rewritten = 0;
	debug(LOG_DEBUG, "https2http: Successfully setup TLS termination bridge for stream %u", client->stream_id);
	return 0;
}
