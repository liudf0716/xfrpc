// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * QUIC Transport Layer implementation using ngtcp2 + OpenSSL.
 *
 * Integrates with libevent for async I/O on the UDP socket and
 * timer management. Provides reliable, ordered, multiplexed
 * stream transport over a hole-punched UDP connection.
 */

#ifdef HAVE_NGTCP2

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#ifdef USE_NGTCP2_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#endif

#include "quic_transport.h"
#include "debug.h"

/* ============================================================
 * Constants
 * ============================================================ */

#define QUIC_MAX_pktlen        1200
#define QUIC_MAX_UDP_PAYLOAD   65535
#define QUIC_MAX_STREAMS       8
#define QUIC_DEFAULT_ALPN      "frp"
#define QUIC_DEFAULT_TIMEOUT   30     /* seconds */
#define QUIC_MAX_WRITE_BUFS    16

/* Maximum buffered data before backpressure */
#define QUIC_MAX_BUFFERED      (4 * 1024 * 1024)

/* ============================================================
 * Internal structures
 * ============================================================ */

/* Per-stream state */
struct quic_stream {
	int64_t             id;
	bool                open;
	bool                fin_sent;
	/* Pending write data */
	struct evbuffer    *write_buf;
};

/* QUIC context */
struct quic_ctx {
	/* libevent */
	struct event_base  *base;
	struct event       *udp_read_event;
	struct event       *timer_event;

	/* UDP socket (hole-punched, already connected) */
	int                 udp_fd;
	struct sockaddr_in  peer_addr;

	/* ngtcp2 */
	ngtcp2_conn        *conn;
	ngtcp2_path         path;
	ngtcp2_cid          dcid;
	ngtcp2_cid          scid;

	/* TLS */
	SSL_CTX            *ssl_ctx;
	SSL                *ssl;

	/* Configuration */
	struct quic_config  config;

	/* Callbacks */
	struct quic_stream_callbacks cbs;

	/* Streams */
	struct quic_stream  streams[QUIC_MAX_STREAMS];
	int                 stream_count;

	/* State */
	bool                handshake_complete;
	bool                connected;
	bool                draining;
	int64_t              next_stream_id;

	/* Write buffer for ngtcp2 output */
	uint8_t             write_buf[QUIC_MAX_UDP_PAYLOAD];
};

/* ============================================================
 * Helpers
 * ============================================================ */

/* Get monotonic timestamp in nanoseconds */
static ngtcp2_tstamp timestamp_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

/* Convert sockaddr_in to ngtcp2_addr */
static void sockaddr_to_ngtcp2_addr(ngtcp2_addr *addr,
				    const struct sockaddr_in *sa)
{
	addr->addrlen = sizeof(*sa);
	memcpy(&addr->addr, sa, sizeof(*sa));
}

/* Find or create stream state */
static struct quic_stream *get_stream(struct quic_ctx *qc, int64_t stream_id)
{
	for (int i = 0; i < qc->stream_count; i++) {
		if (qc->streams[i].id == stream_id)
			return &qc->streams[i];
	}
	if (qc->stream_count < QUIC_MAX_STREAMS) {
		struct quic_stream *s = &qc->streams[qc->stream_count++];
		memset(s, 0, sizeof(*s));
		s->id = stream_id;
		s->write_buf = evbuffer_new();
		return s;
	}
	return NULL;
}

/* ============================================================
 * ngtcp2 callbacks
 * ============================================================ */

static int client_initial_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_ctx *qc = user_data;
	(void)qc;
	/* ngtcp2_crypto handles the initial packet generation */
	return ngtcp2_crypto_client_initial_cb(conn, user_data);
}

static int recv_client_initial_cb(ngtcp2_conn *conn,
				   const ngtcp2_cid *dcid,
				   void *user_data)
{
	(void)conn; (void)dcid; (void)user_data;
	return 0;
}

static int recv_crypto_data_cb(ngtcp2_conn *conn,
				ngtcp2_encryption_level level,
				uint64_t offset,
				const uint8_t *data,
				size_t datalen,
				void *user_data)
{
	struct quic_ctx *qc = user_data;
	int rv;

	rv = ngtcp2_crypto_recv_crypto_data_cb(conn, level, offset,
					       data, datalen, user_data);
	if (rv != 0) {
		debug(LOG_ERR, "QUIC: crypto handshake error: %d", rv);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	/* Check if handshake is complete */
	if (!qc->handshake_complete &&
	    ngtcp2_conn_get_handshake_completed(qc->conn)) {
		qc->handshake_complete = true;
		qc->connected = true;
		debug(LOG_INFO, "QUIC: handshake complete");

		if (qc->cbs.on_conn_ready)
			qc->cbs.on_conn_ready(qc->cbs.user_data);
	}
	return 0;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_ctx *qc = user_data;
	qc->handshake_complete = true;
	qc->connected = true;
	debug(LOG_INFO, "QUIC: handshake completed callback");

	if (qc->cbs.on_conn_ready)
		qc->cbs.on_conn_ready(qc->cbs.user_data);
	return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn,
				uint32_t flags,
				int64_t stream_id,
				uint64_t offset,
				const uint8_t *data,
				size_t datalen,
				void *user_data,
				void *stream_user_data)
{
	struct quic_ctx *qc = user_data;
	(void)conn; (void)flags; (void)offset;
	(void)stream_user_data;

	debug(LOG_DEBUG, "QUIC: received %zu bytes on stream %ld",
	      datalen, (long)stream_id);

	if (qc->cbs.on_recv)
		qc->cbs.on_recv(stream_id, data, datalen, qc->cbs.user_data);

	return 0;
}

static int acked_stream_data_cb(ngtcp2_conn *conn,
				 int64_t stream_id,
					uint64_t offset,
					uint64_t datalen,
					void *user_data,
					void *stream_user_data)
{
	(void)conn; (void)stream_id; (void)offset;
	(void)datalen; (void)user_data; (void)stream_user_data;
	return 0;
}

static int stream_open_cb(ngtcp2_conn *conn,
			   int64_t stream_id,
			   void *user_data)
{
	struct quic_ctx *qc = user_data;
	(void)conn;

	debug(LOG_DEBUG, "QUIC: stream %ld opened", (long)stream_id);
	get_stream(qc, stream_id);
	return 0;
}

static int stream_close_cb(ngtcp2_conn *conn,
			    uint32_t flags,
			    int64_t stream_id,
			    uint64_t app_error_code,
			    void *user_data,
			    void *stream_user_data)
{
	struct quic_ctx *qc = user_data;
	(void)conn; (void)flags; (void)stream_user_data;

	debug(LOG_DEBUG, "QUIC: stream %ld closed (err=%lu)",
	      (long)stream_id, (unsigned long)app_error_code);

	if (qc->cbs.on_close)
		qc->cbs.on_close(stream_id, app_error_code, qc->cbs.user_data);

	/* Clean up stream state */
	for (int i = 0; i < qc->stream_count; i++) {
		if (qc->streams[i].id == stream_id) {
			if (qc->streams[i].write_buf)
				evbuffer_free(qc->streams[i].write_buf);
			qc->streams[i] = qc->streams[--qc->stream_count];
			break;
		}
	}
	return 0;
}

static int stream_reset_cb(ngtcp2_conn *conn,
			    int64_t stream_id,
			    uint64_t final_size,
			   	uint64_t app_error_code,
			    void *user_data,
			    void *stream_user_data)
{
	(void)conn; (void)stream_id; (void)final_size;
	(void)app_error_code; (void)user_data; (void)stream_user_data;
	return 0;
}

static int stream_stop_sending_cb(ngtcp2_conn *conn,
				   int64_t stream_id,
				   	uint64_t app_error_code,
				    void *user_data,
				    void *stream_user_data)
{
	(void)conn; (void)stream_id; (void)app_error_code;
	(void)user_data; (void)stream_user_data;
	return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
		    const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	/* Use OpenSSL RAND for random bytes */
	RAND_bytes(dest, (int)destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *conn,
				     ngtcp2_cid *cid,
				     uint8_t *token,
				     size_t cidlen,
				     void *user_data)
{
	(void)conn; (void)user_data;
	RAND_bytes(cid->data, (int)cidlen);
	cid->datalen = cidlen;
	RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
	return 0;
}

/* update_key and remove_connection_id callbacks removed in ngtcp2 v1.x */

static void delete_crypto_aead_ctx_cb(ngtcp2_conn *conn,
				      ngtcp2_crypto_aead_ctx *aead_ctx,
				      void *user_data)
{
	(void)user_data;
	ngtcp2_crypto_delete_crypto_aead_ctx_cb(conn, aead_ctx, user_data);
}

static void delete_crypto_cipher_ctx_cb(ngtcp2_conn *conn,
					ngtcp2_crypto_cipher_ctx *cipher_ctx,
					void *user_data)
{
	(void)user_data;
	ngtcp2_crypto_delete_crypto_cipher_ctx_cb(conn, cipher_ctx, user_data);
}

static int recv_stateless_reset_cb(ngtcp2_conn *conn,
				    const ngtcp2_pkt_stateless_reset *sr,
				    void *user_data)
{
	(void)conn; (void)sr; (void)user_data;
	debug(LOG_WARNING, "QUIC: received stateless reset");
	return 0;
}

/* ============================================================
 * ngtcp2 callback table
 * ============================================================ */

static ngtcp2_callbacks quic_client_callbacks = {
	.client_initial           = client_initial_cb,
	.recv_client_initial      = recv_client_initial_cb,
	.recv_crypto_data         = recv_crypto_data_cb,
	.handshake_completed      = handshake_completed_cb,
	.recv_stream_data         = recv_stream_data_cb,
	.acked_stream_data_offset = acked_stream_data_cb,
	.stream_open              = stream_open_cb,
	.stream_close             = stream_close_cb,
	.stream_reset             = stream_reset_cb,
	.stream_stop_sending      = stream_stop_sending_cb,
	.rand                     = rand_cb,
	.get_new_connection_id    = get_new_connection_id_cb,
	.delete_crypto_aead_ctx   = delete_crypto_aead_ctx_cb,
	.delete_crypto_cipher_ctx = delete_crypto_cipher_ctx_cb,
	.recv_stateless_reset     = recv_stateless_reset_cb,
};

static ngtcp2_callbacks quic_server_callbacks = {
	.recv_client_initial      = recv_client_initial_cb,
	.recv_crypto_data         = recv_crypto_data_cb,
	.handshake_completed      = handshake_completed_cb,
	.recv_stream_data         = recv_stream_data_cb,
	.acked_stream_data_offset = acked_stream_data_cb,
	.stream_open              = stream_open_cb,
	.stream_close             = stream_close_cb,
	.stream_reset             = stream_reset_cb,
	.stream_stop_sending      = stream_stop_sending_cb,
	.rand                     = rand_cb,
	.get_new_connection_id    = get_new_connection_id_cb,
	.delete_crypto_aead_ctx   = delete_crypto_aead_ctx_cb,
	.delete_crypto_cipher_ctx = delete_crypto_cipher_ctx_cb,
	.recv_stateless_reset     = recv_stateless_reset_cb,
};

/* ============================================================
 * Flush pending ngtcp2 output to UDP socket
 * ============================================================ */

static int quic_flush_write(struct quic_ctx *qc)
{
	ngtcp2_pkt_info pi;
	ngtcp2_path_storage ps;

	ngtcp2_path_storage_init(&ps, (struct sockaddr *)&qc->peer_addr,
				 sizeof(qc->peer_addr), NULL, 0, NULL);

	for (;;) {
		ngtcp2_ssize nwritten;
		int64_t stream_id = -1;
		uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
		ngtcp2_vec datav;

		/* Check if any stream has pending data */
		for (int i = 0; i < qc->stream_count; i++) {
			struct quic_stream *s = &qc->streams[i];
			if (s->write_buf && evbuffer_get_length(s->write_buf) > 0 &&
			    !s->fin_sent) {
				stream_id = s->id;
				flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

				/* Peek at write buffer */
				unsigned char *data = evbuffer_pullup(s->write_buf, -1);
				size_t datalen = evbuffer_get_length(s->write_buf);
				datav.base = data;
				datav.len = datalen;
				break;
			}
		}

		memset(&pi, 0, sizeof(pi));

		if (stream_id >= 0) {
			nwritten = ngtcp2_conn_writev_stream(
				qc->conn, &ps.path, &pi,
				qc->write_buf, sizeof(qc->write_buf),
				&nwritten,
				flags, stream_id,
				&datav, 1,
				timestamp_ns());
		} else {
			nwritten = ngtcp2_conn_writev_stream(
				qc->conn, &ps.path, &pi,
				qc->write_buf, sizeof(qc->write_buf),
				&nwritten,
				NGTCP2_WRITE_STREAM_FLAG_NONE, -1,
				NULL, 0,
				timestamp_ns());
		}

		if (nwritten < 0) {
			if (nwritten == NGTCP2_ERR_WRITE_MORE) {
				/* Consumed data from stream, drain buffer */
				for (int i = 0; i < qc->stream_count; i++) {
					struct quic_stream *s = &qc->streams[i];
					if (s->id == stream_id && s->write_buf) {
						/* ngtcp2_conn_writev_stream tells us
						 * how much was consumed via nwritten
						 * but actually it returns packet length.
						 * We need to track consumed bytes differently. */
						break;
					}
				}
				continue;
			}
			if (nwritten == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
			    nwritten == NGTCP2_ERR_STREAM_NOT_FOUND) {
				/* Try without stream data */
				nwritten = ngtcp2_conn_writev_stream(
					qc->conn, &ps.path, &pi,
					qc->write_buf, sizeof(qc->write_buf),
					&(ngtcp2_ssize){0},
					NGTCP2_WRITE_STREAM_FLAG_NONE, -1,
					NULL, 0,
					timestamp_ns());
				if (nwritten < 0) {
					debug(LOG_ERR, "QUIC: writev_stream error: %s",
					      ngtcp2_strerror((int)nwritten));
					return -1;
				}
			} else if (nwritten == NGTCP2_ERR_DRAINING) {
				qc->draining = true;
				return -1;
			} else {
				debug(LOG_ERR, "QUIC: writev_stream error: %s",
				      ngtcp2_strerror((int)nwritten));
				return -1;
			}
		}

		if (nwritten == 0)
			break;

		/* Send UDP packet */
		ssize_t sent = sendto(qc->udp_fd, qc->write_buf, (size_t)nwritten,
				      0, (struct sockaddr *)&qc->peer_addr,
				      sizeof(qc->peer_addr));
		if (sent < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			debug(LOG_WARNING, "QUIC: sendto failed: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}

/* ============================================================
 * libevent callbacks
 * ============================================================ */

static void udp_read_cb(evutil_socket_t fd, short events, void *ctx)
{
	struct quic_ctx *qc = ctx;
	(void)events;

	uint8_t buf[QUIC_MAX_UDP_PAYLOAD];
	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);

	ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
			     (struct sockaddr *)&from, &from_len);
	if (n <= 0)
		return;

	debug(LOG_DEBUG, "QUIC: received %zd bytes UDP from %s:%d",
	      n, inet_ntoa(from.sin_addr), ntohs(from.sin_port));

	/* Get local address for ngtcp2 path */
	struct sockaddr_in local_addr;
	socklen_t local_len = sizeof(local_addr);
	getsockname(fd, (struct sockaddr *)&local_addr, &local_len);

	/* Feed to ngtcp2 */
	ngtcp2_path path;
	sockaddr_to_ngtcp2_addr(&path.local, &local_addr);
	path.local.addrlen = sizeof(local_addr);
	sockaddr_to_ngtcp2_addr(&path.remote, &from);

	ngtcp2_pkt_info pi;
	memset(&pi, 0, sizeof(pi));

	int rv = ngtcp2_conn_read_pkt(qc->conn, &path, &pi,
				      buf, (size_t)n, timestamp_ns());
	if (rv != 0) {
		if (rv == NGTCP2_ERR_DRAINING) {
			qc->draining = true;
			debug(LOG_INFO, "QUIC: connection draining");
			if (qc->cbs.on_conn_close)
				qc->cbs.on_conn_close(0, qc->cbs.user_data);
			return;
		}
		debug(LOG_WARNING, "QUIC: read_pkt error: %s",
		      ngtcp2_strerror(rv));
		return;
	}

	/* Flush any pending output (ACKs, crypto, stream data) */
	quic_flush_write(qc);
}

static void timer_cb(evutil_socket_t fd, short events, void *ctx)
{
	struct quic_ctx *qc = ctx;
	(void)fd; (void)events;

	ngtcp2_conn_handle_expiry(qc->conn, timestamp_ns());
	quic_flush_write(qc);

	/* Re-arm timer */
	struct timeval tv;
	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(qc->conn);
	ngtcp2_tstamp now = timestamp_ns();

	if (expiry <= now) {
		tv.tv_sec = 0;
		tv.tv_usec = 0;
	} else {
		ngtcp2_tstamp delta = expiry - now;
		tv.tv_sec = (long)(delta / NGTCP2_SECONDS);
		tv.tv_usec = (long)((delta % NGTCP2_SECONDS) / 1000);
	}
	evtimer_add(qc->timer_event, &tv);
}

/* ============================================================
 * Setup TLS
 * ============================================================ */

static SSL_CTX *quic_create_ssl_ctx(const struct quic_config *config)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_method());
	if (!ctx) {
		debug(LOG_ERR, "QUIC: SSL_CTX_new failed");
		return NULL;
	}

	/* Set minimum TLS version */
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

	/* Set ALPN */
	if (config->alpn) {
		const uint8_t *alpn = (const uint8_t *)config->alpn;
		size_t alpn_len = strlen(config->alpn);
		SSL_CTX_set_alpn_protos(ctx, alpn, (unsigned int)alpn_len);
	}

	/* For client: disable certificate verification (P2P, no CA) */
	if (!config->is_server) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	}

#ifdef USE_NGTCP2_WOLFSSL
	/* wolfSSL: configure QUIC on the context */
	if (config->is_server) {
		if (ngtcp2_crypto_wolfssl_configure_server_context(ctx) != 0) {
			debug(LOG_ERR, "QUIC: wolfSSL configure server context failed");
			SSL_CTX_free(ctx);
			return NULL;
		}
	} else {
		if (ngtcp2_crypto_wolfssl_configure_client_context(ctx) != 0) {
			debug(LOG_ERR, "QUIC: wolfSSL configure client context failed");
			SSL_CTX_free(ctx);
			return NULL;
		}
	}
#endif

	return ctx;
}

static SSL *quic_create_ssl(SSL_CTX *ctx, const struct quic_config *config)
{
	SSL *ssl = SSL_new(ctx);
	if (!ssl)
		return NULL;

	/* Set transport as QUIC */
#ifndef USE_NGTCP2_WOLFSSL
	SSL_set_quic_method(ssl, &ngtcp2_crypto_openssl_quic_method);
#endif

	if (!config->is_server) {
		SSL_set_connect_state(ssl);
	} else {
		SSL_set_accept_state(ssl);
	}

	/* Set ALPN */
	if (config->alpn) {
		const uint8_t *alpn = (const uint8_t *)config->alpn;
		size_t alpn_len = strlen(config->alpn);
		SSL_set_alpn_protos(ssl, alpn, (unsigned int)alpn_len);
	}

	return ssl;
}

/* ============================================================
 * Public API
 * ============================================================ */

struct quic_ctx *quic_ctx_new(struct event_base *base,
			      int udp_fd,
			      const struct sockaddr_in *peer_addr,
			      const struct quic_config *config,
			      const struct quic_stream_callbacks *cbs)
{
	if (!base || udp_fd < 0 || !peer_addr || !config || !cbs)
		return NULL;

	struct quic_ctx *qc = calloc(1, sizeof(struct quic_ctx));
	if (!qc)
		return NULL;

	qc->base = base;
	qc->udp_fd = udp_fd;
	qc->peer_addr = *peer_addr;
	qc->config = *config;
	qc->cbs = *cbs;
	qc->next_stream_id = config->is_server ? 1 : 0;

	/* Create TLS context and SSL */
	qc->ssl_ctx = quic_create_ssl_ctx(config);
	if (!qc->ssl_ctx) {
		free(qc);
		return NULL;
	}

	qc->ssl = quic_create_ssl(qc->ssl_ctx, config);
	if (!qc->ssl) {
		SSL_CTX_free(qc->ssl_ctx);
		free(qc);
		return NULL;
	}

	/* Setup ngtcp2 path */
	ngtcp2_path_storage ps;
	struct sockaddr_in local_addr;
	socklen_t addrlen = sizeof(local_addr);
	getsockname(udp_fd, (struct sockaddr *)&local_addr, &addrlen);

	ngtcp2_path_storage_init(&ps,
				 (struct sockaddr *)&local_addr, sizeof(local_addr),
				 (struct sockaddr *)peer_addr, sizeof(*peer_addr),
				 NULL);
	qc->path = ps.path;

	/* Generate random CIDs */
	RAND_bytes(qc->scid.data, 16);
	qc->scid.datalen = 16;
	RAND_bytes(qc->dcid.data, 16);
	qc->dcid.datalen = 16;

	/* ngtcp2 settings */
	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.max_tx_udp_payload_size = QUIC_MAX_UDP_PAYLOAD;
	settings.handshake_timeout = 10 * NGTCP2_SECONDS;

	/* ngtcp2 transport params */
	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	params.initial_max_data = 1024 * 1024;  /* 1MB */
	params.initial_max_stream_data_bidi_local = 512 * 1024;
	params.initial_max_stream_data_bidi_remote = 512 * 1024;
	params.initial_max_stream_data_uni = 0;
	params.initial_max_streams_bidi = config->max_streams;
	params.initial_max_streams_uni = 0;
	params.max_idle_timeout = (uint64_t)config->max_idle_timeout_sec *
				    NGTCP2_SECONDS;

	/* Create ngtcp2 connection */
	int rv;
	if (config->is_server) {
		rv = ngtcp2_conn_server_new(
			&qc->conn, &qc->dcid, &qc->scid,
			&qc->path, NGTCP2_PROTO_VER_V1,
			&quic_server_callbacks,
			&settings, &params, NULL, qc);
	} else {
		rv = ngtcp2_conn_client_new(
			&qc->conn, &qc->dcid, &qc->scid,
			&qc->path, NGTCP2_PROTO_VER_V1,
			&quic_client_callbacks,
			&settings, &params, NULL, qc);
	}

	if (rv != 0) {
		debug(LOG_ERR, "QUIC: ngtcp2_conn_new failed: %s",
		      ngtcp2_strerror(rv));
		SSL_free(qc->ssl);
		SSL_CTX_free(qc->ssl_ctx);
		free(qc);
		return NULL;
	}

	/* Set TLS user data for ngtcp2 crypto callbacks */
	ngtcp2_conn_set_tls_native_handle(qc->conn, qc->ssl);

	/* Set non-blocking */
	evutil_make_socket_nonblocking(udp_fd);

	/* Register libevent UDP read event */
	qc->udp_read_event = event_new(base, udp_fd,
				       EV_READ | EV_PERSIST,
				       udp_read_cb, qc);
	if (!qc->udp_read_event) {
		ngtcp2_conn_del(qc->conn);
		SSL_free(qc->ssl);
		SSL_CTX_free(qc->ssl_ctx);
		free(qc);
		return NULL;
	}
	event_add(qc->udp_read_event, NULL);

	/* Register timer event */
	qc->timer_event = evtimer_new(base, timer_cb, qc);
	if (!qc->timer_event) {
		event_free(qc->udp_read_event);
		ngtcp2_conn_del(qc->conn);
		SSL_free(qc->ssl);
		SSL_CTX_free(qc->ssl_ctx);
		free(qc);
		return NULL;
	}

	debug(LOG_INFO, "QUIC: context created (%s, fd=%d, peer=%s:%d)",
	      config->is_server ? "server" : "client",
	      udp_fd, inet_ntoa(peer_addr->sin_addr), ntohs(peer_addr->sin_port));

	/* For client, trigger initial packet */
	if (!config->is_server) {
		quic_flush_write(qc);

		/* Arm timer */
		ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(qc->conn);
		ngtcp2_tstamp now = timestamp_ns();
		struct timeval tv;
		if (expiry <= now) {
			tv.tv_sec = 0;
			tv.tv_usec = 1000; /* 1ms minimum */
		} else {
			ngtcp2_tstamp delta = expiry - now;
			tv.tv_sec = (long)(delta / NGTCP2_SECONDS);
			tv.tv_usec = (long)((delta % NGTCP2_SECONDS) / 1000);
		}
		evtimer_add(qc->timer_event, &tv);
	}

	return qc;
}

int quic_stream_write(struct quic_ctx *qc, int64_t stream_id,
		      const uint8_t *data, size_t datalen)
{
	if (!qc || !data || datalen == 0)
		return -1;

	if (!qc->connected || qc->draining)
		return -1;

	/* Use default stream if not specified */
	if (stream_id < 0) {
		/* Auto-open a stream on first write (client side) */
		if (qc->stream_count == 0) {
			int rv = ngtcp2_conn_open_bidi_stream(
				qc->conn, &qc->next_stream_id, NULL);
			if (rv != 0) {
				debug(LOG_ERR, "QUIC: open_bidi_stream failed: %d", rv);
				return -1;
			}
			get_stream(qc, qc->next_stream_id);
			stream_id = qc->next_stream_id;
			qc->next_stream_id += 4; /* next bidi stream */
		} else {
			stream_id = qc->streams[0].id;
		}
	}

	struct quic_stream *s = get_stream(qc, stream_id);
	if (!s) {
		debug(LOG_ERR, "QUIC: stream %ld not found", (long)stream_id);
		return -1;
	}

	/* Buffer the data */
	if (s->write_buf)
		evbuffer_add(s->write_buf, data, datalen);

	/* Try to flush */
	quic_flush_write(qc);

	return 0;
}

ssize_t quic_stream_write_evbuf(struct quic_ctx *qc, int64_t stream_id,
				struct evbuffer *buf)
{
	if (!qc || !buf)
		return -1;

	size_t len = evbuffer_get_length(buf);
	if (len == 0)
		return 0;

	if (!qc->connected || qc->draining)
		return -1;

	if (stream_id < 0) {
		if (qc->stream_count == 0) {
			int rv = ngtcp2_conn_open_bidi_stream(
				qc->conn, &qc->next_stream_id, NULL);
			if (rv != 0) return -1;
			get_stream(qc, qc->next_stream_id);
			stream_id = qc->next_stream_id;
			qc->next_stream_id += 4;
		} else {
			stream_id = qc->streams[0].id;
		}
	}

	struct quic_stream *s = get_stream(qc, stream_id);
	if (!s || !s->write_buf)
		return -1;

	/* Transfer data from input buf to stream write buf */
	int ret = evbuffer_add_buffer(s->write_buf, buf);
	if (ret < 0) return -1;

	quic_flush_write(qc);
	return (ssize_t)len;
}

int quic_stream_close(struct quic_ctx *qc, int64_t stream_id,
		      uint64_t app_error)
{
	if (!qc || !qc->conn)
		return -1;

	int rv = ngtcp2_conn_shutdown_stream(qc->conn, 0, stream_id, app_error);
	if (rv != 0) {
		debug(LOG_WARNING, "QUIC: shutdown_stream %ld failed: %s",
		      (long)stream_id, ngtcp2_strerror(rv));
		return -1;
	}

	quic_flush_write(qc);
	return 0;
}

void quic_ctx_free(struct quic_ctx *qc)
{
	if (!qc)
		return;

	debug(LOG_INFO, "QUIC: destroying context");

	/* Send connection close */
	if (qc->conn && !qc->draining) {
		ngtcp2_ccerr ccerr;
		ngtcp2_ccerr_default(&ccerr);
		ngtcp2_ccerr_set_application_error(&ccerr, NGTCP2_NO_ERROR, NULL, 0);
		ngtcp2_ssize nwritten = ngtcp2_conn_write_connection_close(
			qc->conn, NULL, NULL, qc->write_buf, sizeof(qc->write_buf),
			&ccerr, timestamp_ns());
		/* Best-effort send */
		if (nwritten > 0) {
			sendto(qc->udp_fd, qc->write_buf,
			       (size_t)nwritten, 0,
			       (struct sockaddr *)&qc->peer_addr,
			       sizeof(qc->peer_addr));
		}
	}

	if (qc->timer_event) {
		evtimer_del(qc->timer_event);
		event_free(qc->timer_event);
	}
	if (qc->udp_read_event) {
		event_del(qc->udp_read_event);
		event_free(qc->udp_read_event);
	}

	/* Free streams */
	for (int i = 0; i < qc->stream_count; i++) {
		if (qc->streams[i].write_buf)
			evbuffer_free(qc->streams[i].write_buf);
	}

	if (qc->conn)
		ngtcp2_conn_del(qc->conn);
	if (qc->ssl)
		SSL_free(qc->ssl);
	if (qc->ssl_ctx)
		SSL_CTX_free(qc->ssl_ctx);

	free(qc);
}

bool quic_ctx_is_ready(const struct quic_ctx *qc)
{
	return qc && qc->connected && !qc->draining;
}

#endif /* HAVE_NGTCP2 */
