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

	if (X509_sign(x509, pkey, EVP_sha256()) <= 0) {
		X509_free(x509);
		EVP_PKEY_free(pkey);
		return -1;
	}

	int ret1 = SSL_CTX_use_certificate(ctx, x509);
	int ret2 = SSL_CTX_use_PrivateKey(ctx, pkey);
	int ret3 = SSL_CTX_check_private_key(ctx);

	X509_free(x509);
	EVP_PKEY_free(pkey);

	return (ret1 > 0 && ret2 > 0 && ret3 == 1) ? 0 : -1;
}

int https2http_init_service(struct proxy_service *ps)
{
	if (!ps || !is_https2http_proxy(ps)) return 0;
	if (ps->ssl_ctx) return 0;

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		debug(LOG_ERR, "https2http: [%s] Failed to create SSL_CTX", ps->proxy_name);
		return -1;
	}

#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
	SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif

	int loaded = 0;
	if (ps->plugin_crt_path && ps->plugin_key_path) {
		if (SSL_CTX_use_certificate_file(ctx, ps->plugin_crt_path, SSL_FILETYPE_PEM) > 0 &&
		    SSL_CTX_use_PrivateKey_file(ctx, ps->plugin_key_path, SSL_FILETYPE_PEM) > 0 &&
		    SSL_CTX_check_private_key(ctx) == 1) {
			debug(LOG_INFO, "https2http: [%s] Successfully loaded cert [%s] and key [%s]",
			      ps->proxy_name, ps->plugin_crt_path, ps->plugin_key_path);
			loaded = 1;
		} else {
			char err_buf[256];
			ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
			debug(LOG_ERR, "https2http: [%s] Failed to load/verify cert [%s] or key [%s]: %s",
			      ps->proxy_name, ps->plugin_crt_path, ps->plugin_key_path, err_buf);
			ERR_clear_error();
			SSL_CTX_free(ctx);
			ctx = SSL_CTX_new(TLS_server_method());
			if (!ctx) return -1;
		}
	}

	if (!loaded) {
		debug(LOG_INFO, "https2http: [%s] Generating self-signed RSA certificate", ps->proxy_name);
		if (generate_self_signed_cert(ctx) < 0) {
			debug(LOG_ERR, "https2http: [%s] Failed to generate self-signed cert", ps->proxy_name);
			SSL_CTX_free(ctx);
			return -1;
		}
	}

	ps->ssl_ctx = ctx;
	return 0;
}

void https2http_free_service(struct proxy_service *ps)
{
	if (!ps) return;
	if (ps->ssl_ctx) {
		SSL_CTX_free(ps->ssl_ctx);
		ps->ssl_ctx = NULL;
	}
}

void https2http_client_cleanup(struct proxy_client *client)
{
	if (!client) return;

	if (client->ssl_bev) {
		bufferevent_free(client->ssl_bev);
		client->ssl_bev = NULL;
	}
	if (client->bridge_bev) {
		int bridge_fd = bufferevent_getfd(client->bridge_bev);
		struct evbuffer *out = bufferevent_get_output(client->bridge_bev);
		if (bridge_fd >= 0 && out) {
			while (evbuffer_get_length(out) > 0) {
				int n = evbuffer_write(out, bridge_fd);
				if (n <= 0) break;
			}
		}
		bufferevent_free(client->bridge_bev);
		client->bridge_bev = NULL;
	}
	if (client->bridge_fd >= 0) {
		close(client->bridge_fd);
		client->bridge_fd = -1;
	}
	if (client->enc_pending && evbuffer_get_length(client->enc_pending) == 0) {
		evbuffer_free(client->enc_pending);
		client->enc_pending = NULL;
	}
}

static char *rewrite_http_host(const char *req, size_t req_len, const char *new_host, size_t *out_len)
{
	const char *hdr_end = strstr(req, "\r\n\r\n");
	if (!hdr_end) {
		return NULL;
	}
	size_t hdr_len = (hdr_end - req) + 4;

	size_t max_buf_len = req_len + strlen(new_host) + 128;
	char *buf = malloc(max_buf_len);
	if (!buf) return NULL;

	char *out = buf;
	const char *p = req;
	int host_replaced = 0;

	while (p < hdr_end) {
		const char *line_end = strstr(p, "\r\n");
		if (!line_end || line_end > hdr_end) break;

		if (strncasecmp(p, "Host:", 5) == 0) {
			if (!host_replaced) {
				out += sprintf(out, "Host: %s\r\n", new_host);
				host_replaced = 1;
			}
			/* Skip duplicate Host headers to avoid header smuggling & heap growth */
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
		struct evbuffer_ptr pos = evbuffer_search(src, "\r\n\r\n", 4, NULL);
		if (pos.pos < 0) {
			/* Wait until complete HTTP headers arrive, unless buffer exceeds 64KB */
			if (len < 65536) {
				return;
			}
			client->header_rewritten = 1;
		} else {
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
			client->header_rewritten = 1;
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
	bufferevent_write_buffer(client->ssl_bev, src);

	/* Watermark backpressure: if ssl_bev output buffer exceeds 64KB, stop reading from local HTTP */
	if (evbuffer_get_length(bufferevent_get_output(client->ssl_bev)) >= 65536) {
		bufferevent_disable(bev, EV_READ);
	}
}

void https2http_trigger_shutdown(struct proxy_client *client)
{
	if (!client || !client->ssl_bev) return;

	struct evbuffer *ssl_out = bufferevent_get_output(client->ssl_bev);
	if (!ssl_out || evbuffer_get_length(ssl_out) == 0) {
		SSL *ssl = bufferevent_openssl_get_ssl(client->ssl_bev);
		if (ssl) {
			SSL_shutdown(ssl);
		}
		evutil_socket_t fd = bufferevent_getfd(client->ssl_bev);
		if (fd >= 0) {
			shutdown(fd, SHUT_WR);
		}
	}
}

static void https2http_ssl_write_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	if (!client) return;

	if (client->pending_close) {
		struct evbuffer *out = bufferevent_get_output(bev);
		if (!out || evbuffer_get_length(out) == 0) {
			https2http_trigger_shutdown(client);
		}
		return;
	}

	if (!client->local_proxy_bev) return;

	struct common_conf *c_conf = get_common_config();
	int has_window = (!c_conf->tcp_mux) || (client->stream.send_window > 0);

	if (has_window) {
		struct evbuffer *out = bufferevent_get_output(bev);
		if (evbuffer_get_length(out) <= 16384) {
			bufferevent_enable(client->local_proxy_bev, EV_READ);
		}
	}
}

void https2http_ssl_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	if (!client) return;

	int is_eof = (what & BEV_EVENT_EOF);
	unsigned long ossl_err = 0;
	if (what & BEV_EVENT_ERROR) {
		ossl_err = bufferevent_get_openssl_error(bev);
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
		if (ERR_GET_REASON(ossl_err) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
			is_eof = 1;
		}
#endif
	}

	if (what & BEV_EVENT_CONNECTED) {
		debug(LOG_DEBUG, "https2http: TLS handshake accepted for client stream %u", client->stream_id);
	} else if (is_eof) {
		debug(LOG_DEBUG, "https2http: TLS session EOF for stream %u", client->stream_id);
		if (!client->header_rewritten) {
			client->header_rewritten = 1;
		}
		https2http_ssl_read_cb(bev, ctx);
		if (client->local_proxy_bev) {
			int local_fd = bufferevent_getfd(client->local_proxy_bev);
			if (local_fd >= 0) {
				struct evbuffer *out = bufferevent_get_output(client->local_proxy_bev);
				if (out) {
					while (evbuffer_get_length(out) > 0) {
						int n = evbuffer_write(out, local_fd);
						if (n <= 0) break;
					}
				}
				if (out && evbuffer_get_length(out) > 0) {
					debug(LOG_INFO, "Stream %u: https2http EOF, %zu bytes pending in local out buffer, deferring shutdown",
					      client->stream_id, evbuffer_get_length(out));
					client->pending_shutdown_wr = 1;
				} else {
					debug(LOG_INFO, "Stream %u: https2http EOF, shutting down local write (fd=%d)",
					      client->stream_id, local_fd);
					shutdown(local_fd, SHUT_WR);
					client->pending_shutdown_wr = 0;
				}
			}
		} else if (client->pending_close) {
			https2http_try_finish_close(client);
		}
	} else if (what & BEV_EVENT_ERROR) {
		char err_buf[256];
		ERR_error_string_n(ossl_err, err_buf, sizeof(err_buf));
		debug(LOG_DEBUG, "https2http: TLS session error (what=0x%x, ossl_err=%lu: %s)", what, ossl_err, err_buf);
		if (client->local_proxy_bev) {
			bufferevent_free(client->local_proxy_bev);
			client->local_proxy_bev = NULL;
		}
		del_proxy_client_by_stream_id(client->stream_id);
	}
}

int https2http_bridge_drain(struct proxy_client *client)
{
	if (!client || !client->ctl_bev) return 0;

	struct common_conf *c_conf = get_common_config();
	struct evbuffer *bridge_in = client->bridge_bev ? bufferevent_get_input(client->bridge_bev) : NULL;

	/* Apply encryption/compression if enabled */
	if (client->use_encryption || client->use_compression) {
		/* Flush any previously-encrypted data stashed due to window exhaustion */
		if (client->enc_pending && evbuffer_get_length(client->enc_pending) > 0) {
			if (!c_conf->tcp_mux) {
				struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
				evbuffer_add_buffer(dst, client->enc_pending);
			} else {
				while (evbuffer_get_length(client->enc_pending) > 0) {
					int written = tmux_stream_write(client->ctl_bev, client->enc_pending, &client->stream);
					if (written < 0) {
						return written;
					}
					if (written == 0) {
						if (client->bridge_bev)
							bufferevent_disable(client->bridge_bev, EV_READ);
						if (client->local_proxy_bev)
							bufferevent_disable(client->local_proxy_bev, EV_READ);
						return 1;
					}
				}
			}
		}

		if (!bridge_in || evbuffer_get_length(bridge_in) == 0)
			return 0;

		struct evbuffer *processed = evbuffer_new();
		if (!processed) return -1;
		proxy_crypto_encode_evbuffer(client, bridge_in, processed);

		if (!c_conf->tcp_mux) {
			struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
			evbuffer_add_buffer(dst, processed);
			evbuffer_free(processed);
			return 0;
		}

		while (evbuffer_get_length(processed) > 0) {
			int written = tmux_stream_write(client->ctl_bev, processed, &client->stream);
			if (written < 0) {
				evbuffer_free(processed);
				return written;
			}
			if (written == 0) {
				if (!client->enc_pending)
					client->enc_pending = evbuffer_new();
				if (client->enc_pending) {
					evbuffer_add_buffer(client->enc_pending, processed);
				}
				evbuffer_free(processed);
				if (client->bridge_bev)
					bufferevent_disable(client->bridge_bev, EV_READ);
				if (client->local_proxy_bev)
					bufferevent_disable(client->local_proxy_bev, EV_READ);
				return 1;
			}
		}
		evbuffer_free(processed);
		return 0;
	}

	/* Plain path (no frp crypto/compression) */
	if (!c_conf->tcp_mux) {
		if (bridge_in && evbuffer_get_length(bridge_in) > 0) {
			struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
			evbuffer_add_buffer(dst, bridge_in);
		}
		return 0;
	}

	if (bridge_in) {
		while (evbuffer_get_length(bridge_in) > 0) {
			int written = tmux_stream_write(client->ctl_bev, bridge_in, &client->stream);
			if (written < 0) {
				return written;
			}
			if (written == 0) {
				if (client->bridge_bev)
					bufferevent_disable(client->bridge_bev, EV_READ);
				if (client->local_proxy_bev)
					bufferevent_disable(client->local_proxy_bev, EV_READ);
				return 1;
			}
		}
	}

	return 0;
}

int https2http_try_finish_close(struct proxy_client *client)
{
	if (!client || !client->ctl_bev) return 0;
	if (!client->bridge_eof) return 0;

	if (https2http_bridge_drain(client) < 0) {
		del_proxy_client_by_stream_id(client->stream.id ? client->stream.id : client->stream_id);
		return -1;
	}

	int has_pending = 0;
	if (client->enc_pending && evbuffer_get_length(client->enc_pending) > 0)
		has_pending = 1;
	if (client->bridge_bev && evbuffer_get_length(bufferevent_get_input(client->bridge_bev)) > 0)
		has_pending = 1;

	if (has_pending) {
		return 0;
	}

	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		if (client->stream.send_window == 0) {
			return 0;
		}
		debug(LOG_INFO, "Stream %u: TLS bridge fully EOF drained, sending FIN", client->stream_id);
		client->pending_close = 0;
		tmux_stream_close(client->ctl_bev, &client->stream);
	} else {
		client->pending_close = 0;
		if (client->ctl_bev) {
			struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
			int ctl_fd = bufferevent_getfd(client->ctl_bev);
			if (ctl_fd >= 0 && dst) {
				while (evbuffer_get_length(dst) > 0) {
					int n = evbuffer_write(dst, ctl_fd);
					if (n <= 0) break;
				}
			}
			bufferevent_free(client->ctl_bev);
			client->ctl_bev = NULL;
		}
		del_proxy_client_by_stream_id(client->stream.id ? client->stream.id : client->stream_id);
	}

	return 1;
}

void https2http_bridge_write_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	if (!client) return;

	if (client->pending_shutdown_bridge) {
		struct evbuffer *out = bufferevent_get_output(bev);
		if (!out || evbuffer_get_length(out) == 0) {
			int bridge_fd = bufferevent_getfd(bev);
			if (bridge_fd >= 0) {
				debug(LOG_INFO, "Stream %u: bridge output drained, shutting down bridge write (fd=%d)",
				      client->stream_id, bridge_fd);
				shutdown(bridge_fd, SHUT_WR);
			}
			client->pending_shutdown_bridge = 0;
		}
	}
}

void https2http_bridge_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	(void)bev;
	struct proxy_client *client = (struct proxy_client *)ctx;
	if (!client) return;

	if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		client->bridge_eof = 1;
		https2http_try_finish_close(client);
	}
}

void https2http_bridge_read_cb(struct bufferevent *bev, void *ctx)
{
	(void)bev;
	struct proxy_client *client = (struct proxy_client *)ctx;
	if (!client) return;

	int ret = https2http_bridge_drain(client);
	if (ret < 0) {
		del_proxy_client_by_stream_id(client->stream.id ? client->stream.id : client->stream_id);
		return;
	}

	if (client->bridge_eof) {
		https2http_try_finish_close(client);
	}
}

int https2http_setup(struct proxy_client *client)
{
	if (!client || !client->ps || !client->base) return -1;

	if (!client->ps->ssl_ctx) {
		if (https2http_init_service(client->ps) < 0 || !client->ps->ssl_ctx) {
			debug(LOG_ERR, "https2http: Failed to get SSL_CTX for service %s", client->ps->proxy_name);
			return -1;
		}
	}

	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp) < 0) {
		debug(LOG_ERR, "https2http: socketpair failed: %s", strerror(errno));
		return -1;
	}

	SSL *ssl = SSL_new(client->ps->ssl_ctx);
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
	bufferevent_setcb(client->ssl_bev, https2http_ssl_read_cb, https2http_ssl_write_cb, https2http_ssl_event_cb, client);
	bufferevent_setwatermark(client->ssl_bev, EV_WRITE, 16384, 0);
	bufferevent_enable(client->ssl_bev, EV_READ | EV_WRITE);

	client->bridge_bev = bufferevent_socket_new(client->base, sp[1], BEV_OPT_CLOSE_ON_FREE);
	if (!client->bridge_bev) {
		debug(LOG_ERR, "https2http: Failed to create bridge bufferevent");
		close(sp[1]);
		client->bridge_fd = -1;
		bufferevent_free(client->ssl_bev);
		client->ssl_bev = NULL;
		return -1;
	}

	/* Ownership of sp[1] is now transferred to bridge_bev */
	client->bridge_fd = -1;

	bufferevent_setcb(client->bridge_bev, https2http_bridge_read_cb, https2http_bridge_write_cb, https2http_bridge_event_cb, client);
	bufferevent_enable(client->bridge_bev, EV_READ | EV_WRITE);

	client->header_rewritten = 0;
	debug(LOG_DEBUG, "https2http: Successfully setup TLS termination bridge for stream %u", client->stream_id);
	return 0;
}
