// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * QUIC Client Transport — connects xfrpc to frps over QUIC (ngtcp2).
 * Uses a socketpair to bridge QUIC streams with libevent bufferevents.
 */

#ifdef HAVE_NGTCP2

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

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
#include <openssl/rand.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#endif

#include "quic_client_transport.h"
#include "debug.h"

#define QC_MAX_UDP_PAYLOAD   65527
#define QC_HANDSHAKE_TIMEOUT 10
#define QC_MAX_IDLE_SEC      120
#define QC_RELAY_BUF_SIZE    65536

struct quic_client_ctx {
	struct event_base  *base;
	struct event       *udp_read_ev;
	struct event       *timer_ev;
	int                 udp_fd;
	ngtcp2_conn        *conn;
	ngtcp2_cid          dcid;
	ngtcp2_cid          scid;
	ngtcp2_path         path;
	SSL_CTX            *ssl_ctx;
	SSL                *ssl;
	int                 sp_fd;
	int                 bev_fd;
	struct event       *sp_read_ev;
	struct evbuffer    *quic_out_buf;
	int                 handshake_done;
	int                 draining;
	uint8_t             wbuf[QC_MAX_UDP_PAYLOAD];
};

static ngtcp2_tstamp qc_ts(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

static void qc_flush_sp(struct quic_client_ctx *qc)
{
	if (!qc->quic_out_buf || evbuffer_get_length(qc->quic_out_buf) == 0)
		return;
	int n = evbuffer_write(qc->quic_out_buf, qc->sp_fd);
	if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		debug(LOG_ERR, "QUIC client: sp write err: %s", strerror(errno));
}

static int qc_write_udp(struct quic_client_ctx *qc)
{
	ngtcp2_path_storage ps;
	struct sockaddr_in la;
	socklen_t al = sizeof(la);
	getsockname(qc->udp_fd, (struct sockaddr *)&la, &al);
	ngtcp2_path_storage_init(&ps, (struct sockaddr *)&la, al, NULL, 0, NULL);
	ngtcp2_pkt_info pi;
	memset(&pi, 0, sizeof(pi));

	for (;;) {
		ngtcp2_ssize n = ngtcp2_conn_writev_stream(
			qc->conn, &ps.path, &pi,
			qc->wbuf, sizeof(qc->wbuf), NULL,
			NGTCP2_WRITE_STREAM_FLAG_NONE,
			-1, NULL, 0, qc_ts());
		if (n <= 0) {
			if (n == NGTCP2_ERR_WRITE_MORE) continue;
			break;
		}
		ssize_t sent = send(qc->udp_fd, qc->wbuf, (size_t)n, 0);
		if (sent < 0) return -1;
	}

	ngtcp2_tstamp exp = ngtcp2_conn_get_expiry(qc->conn);
	if (exp != UINT64_MAX) {
		ngtcp2_tstamp now = qc_ts();
		uint64_t d = exp > now ? exp - now : 0;
		struct timeval tv = {
			.tv_sec = (long)(d / NGTCP2_SECONDS),
			.tv_usec = (long)((d % NGTCP2_SECONDS) / 1000)
		};
		if (tv.tv_sec == 0 && tv.tv_usec == 0) tv.tv_usec = 1000;
		event_add(qc->timer_ev, &tv);
	}
	return 0;
}

/* ---- ngtcp2 callbacks ---- */

static int qc_client_initial(ngtcp2_conn *conn, void *ud)
{
	(void)ud;
	return ngtcp2_crypto_client_initial_cb(conn, ud);
}

static int qc_recv_crypto(ngtcp2_conn *conn, ngtcp2_encryption_level level,
			  uint64_t off, const uint8_t *data, size_t len,
			  void *ud)
{
	struct quic_client_ctx *qc = ud;
	(void)off;
	int rv = ngtcp2_crypto_recv_crypto_data_cb(conn, level, 0, data, len, ud);
	if (rv != 0) return NGTCP2_ERR_CALLBACK_FAILURE;
	if (!qc->handshake_done && ngtcp2_conn_get_handshake_completed(conn)) {
		qc->handshake_done = 1;
		debug(LOG_INFO, "QUIC client: handshake complete");
	}
	return 0;
}

static int qc_handshake_done(ngtcp2_conn *conn, void *ud)
{
	(void)conn;
	struct quic_client_ctx *qc = ud;
	qc->handshake_done = 1;
	return 0;
}

static int qc_recv_stream(ngtcp2_conn *conn, uint32_t flags,
			  int64_t sid, uint64_t off,
			  const uint8_t *data, size_t len,
			  void *ud, void *sud)
{
	struct quic_client_ctx *qc = ud;
	(void)conn; (void)flags; (void)sid; (void)off; (void)sud;
	if (len > 0) {
		evbuffer_add(qc->quic_out_buf, data, len);
		qc_flush_sp(qc);
	}
	return 0;
}

static int qc_acked(ngtcp2_conn *c, int64_t sid, uint64_t off,
		    uint64_t len, void *ud, void *sud)
{
	(void)c; (void)sid; (void)off; (void)len; (void)ud; (void)sud;
	return 0;
}


static int qc_stream_open(ngtcp2_conn *c, int64_t sid, void *ud)
{
	(void)c; (void)sid; (void)ud; return 0;
}

static int qc_stream_close(ngtcp2_conn *c, uint32_t flags, int64_t sid,
			   uint64_t ec, void *ud, void *sud)
{
	(void)c; (void)flags; (void)sid; (void)ec; (void)ud; (void)sud;
	return 0;
}

static void qc_rand(uint8_t *dest, size_t len,
			 const ngtcp2_rand_ctx *ctx)
{
	(void)ctx;
	RAND_bytes(dest, (int)len);
}

static void qc_del_aead(ngtcp2_conn *c, ngtcp2_crypto_aead_ctx *a, void *ud)
{
	(void)ud;
	ngtcp2_crypto_delete_crypto_aead_ctx_cb(c, a, ud);
}

static void qc_del_cipher(ngtcp2_conn *c, ngtcp2_crypto_cipher_ctx *ci, void *ud)
{
	(void)ud;
	ngtcp2_crypto_delete_crypto_cipher_ctx_cb(c, ci, ud);
}

static ngtcp2_callbacks qc_cbs = {
	.client_initial           = qc_client_initial,
	.recv_crypto_data         = qc_recv_crypto,
	.handshake_completed      = qc_handshake_done,
	.recv_stream_data         = qc_recv_stream,
	.acked_stream_data_offset = qc_acked,
	.stream_open              = qc_stream_open,
	.stream_close             = qc_stream_close,
	.rand                     = qc_rand,
	.delete_crypto_aead_ctx   = qc_del_aead,
	.delete_crypto_cipher_ctx = qc_del_cipher,
};

/* ---- libevent callbacks ---- */

static void qc_udp_read_cb(evutil_socket_t fd, short what, void *arg)
{
	struct quic_client_ctx *qc = arg;
	(void)what;
	uint8_t buf[QC_MAX_UDP_PAYLOAD];
	struct sockaddr_storage pa;
	socklen_t pal = sizeof(pa);
	ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
			     (struct sockaddr *)&pa, &pal);
	if (n <= 0) return;

	struct sockaddr_in la;
	socklen_t lal = sizeof(la);
	getsockname(fd, (struct sockaddr *)&la, &lal);

	ngtcp2_path_storage path_st;
	ngtcp2_path_storage_init(&path_st,
				 (struct sockaddr *)&la, lal,
				 (struct sockaddr *)&pa, pal, NULL);

	int rv = ngtcp2_conn_read_pkt(qc->conn, &path_st.path, NULL,
				      buf, (size_t)n, qc_ts());
	if (rv != 0 && ngtcp2_err_is_fatal(rv)) {
		qc->draining = 1;
		return;
	}
	qc_flush_sp(qc);
	qc_write_udp(qc);
}

static void qc_sp_read_cb(evutil_socket_t fd, short what, void *arg)
{
	struct quic_client_ctx *qc = arg;
	(void)what;
	uint8_t buf[QC_RELAY_BUF_SIZE];
	ssize_t n = read(fd, buf, sizeof(buf));
	if (n <= 0) { if (n < 0 && errno == EAGAIN) return; return; }

	ngtcp2_vec dv = { .base = buf, .len = (size_t)n };
	ngtcp2_path_storage ps;
	struct sockaddr_in la;
	socklen_t al = sizeof(la);
	getsockname(qc->udp_fd, (struct sockaddr *)&la, &al);
	ngtcp2_path_storage_init(&ps, (struct sockaddr *)&la, al, NULL, 0, NULL);
	ngtcp2_pkt_info pi;
	memset(&pi, 0, sizeof(pi));

	ngtcp2_conn_writev_stream(qc->conn, &ps.path, &pi,
				  qc->wbuf, sizeof(qc->wbuf), NULL,
				  NGTCP2_WRITE_STREAM_FLAG_NONE,
				  0, &dv, 1, qc_ts());
	qc_write_udp(qc);
}

static void qc_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	struct quic_client_ctx *qc = arg;
	(void)fd; (void)what;
	if (ngtcp2_conn_handle_expiry(qc->conn, qc_ts()) != 0) {
		qc->draining = 1;
		return;
	}
	qc_write_udp(qc);
}

static void qc_free(struct quic_client_ctx *qc)
{
	if (!qc) return;
	if (qc->conn) ngtcp2_conn_del(qc->conn);
	if (qc->ssl) SSL_free(qc->ssl);
	if (qc->ssl_ctx) SSL_CTX_free(qc->ssl_ctx);
	if (qc->udp_read_ev) event_free(qc->udp_read_ev);
	if (qc->timer_ev) event_free(qc->timer_ev);
	if (qc->sp_read_ev) event_free(qc->sp_read_ev);
	if (qc->quic_out_buf) evbuffer_free(qc->quic_out_buf);
	if (qc->udp_fd >= 0) close(qc->udp_fd);
	if (qc->sp_fd >= 0) close(qc->sp_fd);
	free(qc);
}

/* ============================================================
 * Public API
 * ============================================================ */

int quic_transport_available(void) { return 1; }

struct bufferevent *quic_connect_to_server(struct event_base *base,
					   const char *server_addr, int port)
{
	if (!base || !server_addr || port <= 0) return NULL;

	struct quic_client_ctx *qc = calloc(1, sizeof(*qc));
	if (!qc) return NULL;
	qc->udp_fd = qc->sp_fd = qc->bev_fd = -1;

	/* socketpair */
	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp) < 0) {
		free(qc); return NULL;
	}
	qc->sp_fd = sp[0]; qc->bev_fd = sp[1];

	/* UDP connect */
	qc->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (qc->udp_fd < 0) goto fail;

	struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
	struct addrinfo *res = NULL;
	char ps[16];
	snprintf(ps, sizeof(ps), "%d", port);
	if (getaddrinfo(server_addr, ps, &hints, &res) != 0 || !res) goto fail;
	if (connect(qc->udp_fd, res->ai_addr, (int)res->ai_addrlen) < 0) {
		freeaddrinfo(res); goto fail;
	}

	/* local addr for ngtcp2 path */
	struct sockaddr_in la;
	socklen_t lal = sizeof(la);
	getsockname(qc->udp_fd, (struct sockaddr *)&la, &lal);

	ngtcp2_path_storage path_st;
	ngtcp2_path_storage_init(&path_st,
				 (struct sockaddr *)&la, lal,
				 res->ai_addr, (socklen_t)res->ai_addrlen, NULL);
	qc->path = path_st.path;
	freeaddrinfo(res);

	debug(LOG_INFO, "QUIC client: UDP -> %s:%d", server_addr, port);

	/* TLS */
#ifdef USE_NGTCP2_WOLFSSL
	qc->ssl_ctx = SSL_CTX_new(wolfTLSv1_3_client_method());
#else
	qc->ssl_ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(qc->ssl_ctx, TLS1_3_VERSION);
#endif
	if (!qc->ssl_ctx) goto fail;
	unsigned char alpn[] = { 3, 'f', 'r', 'p' };
	SSL_CTX_set_alpn_protos(qc->ssl_ctx, alpn, sizeof(alpn));
	qc->ssl = SSL_new(qc->ssl_ctx);
	if (!qc->ssl) goto fail;

	/* CIDs */
	RAND_bytes(qc->scid.data, 8); qc->scid.datalen = 8;
	RAND_bytes(qc->dcid.data, 8); qc->dcid.datalen = 8;

	/* ngtcp2 settings */
	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.max_tx_udp_payload_size = QC_MAX_UDP_PAYLOAD;
	settings.handshake_timeout = QC_HANDSHAKE_TIMEOUT * NGTCP2_SECONDS;

	ngtcp2_transport_params tp;
	ngtcp2_transport_params_default(&tp);
	tp.initial_max_data = 1024 * 1024;
	tp.initial_max_stream_data_bidi_local = 512 * 1024;
	tp.initial_max_stream_data_bidi_remote = 512 * 1024;
	tp.initial_max_streams_bidi = 100;
	tp.max_idle_timeout = (uint64_t)QC_MAX_IDLE_SEC * NGTCP2_SECONDS;

	int rv = ngtcp2_conn_client_new(&qc->conn, &qc->dcid, &qc->scid,
					&qc->path, NGTCP2_PROTO_VER_V1,
					&qc_cbs, &settings, &tp, NULL, qc);
	if (rv != 0) {
		debug(LOG_ERR, "QUIC client: ngtcp2 err: %s", ngtcp2_strerror(rv));
		goto fail;
	}
	ngtcp2_conn_set_tls_native_handle(qc->conn, qc->ssl);

	/* events */
	qc->base = base;
	qc->udp_read_ev = event_new(base, qc->udp_fd, EV_READ|EV_PERSIST,
				    qc_udp_read_cb, qc);
	qc->timer_ev = evtimer_new(base, qc_timer_cb, qc);
	qc->sp_read_ev = event_new(base, qc->sp_fd, EV_READ|EV_PERSIST,
				   qc_sp_read_cb, qc);
	qc->quic_out_buf = evbuffer_new();
	if (!qc->udp_read_ev || !qc->timer_ev || !qc->sp_read_ev || !qc->quic_out_buf)
		goto fail;

	/* kick off handshake — generate Initial packet */
	qc_write_udp(qc);
	event_add(qc->udp_read_ev, NULL);
	event_add(qc->sp_read_ev, NULL);

	/* poll for handshake */
	time_t t0 = time(NULL);
	while (!qc->handshake_done) {
		event_base_loop(base, EVLOOP_ONCE | EVLOOP_NONBLOCK);
		if (qc->draining) goto fail;
		if (time(NULL) - t0 > QC_HANDSHAKE_TIMEOUT) {
			debug(LOG_ERR, "QUIC client: handshake timeout");
			goto fail;
		}
		usleep(10000);
	}

	debug(LOG_INFO, "QUIC client: connected to %s:%d", server_addr, port);

	struct bufferevent *bev = bufferevent_socket_new(base, qc->bev_fd,
							BEV_OPT_CLOSE_ON_FREE);
	if (!bev) goto fail;
	qc->bev_fd = -1;
	return bev;

fail:
	if (qc->bev_fd >= 0) close(qc->bev_fd);
	qc_free(qc);
	return NULL;
}

#else /* !HAVE_NGTCP2 */

#include "quic_client_transport.h"
#include "debug.h"
int quic_transport_available(void) { return 0; }
struct bufferevent *quic_connect_to_server(struct event_base *b,
					   const char *a, int p)
{
	(void)b; (void)a; (void)p;
	debug(LOG_ERR, "QUIC not compiled in");
	return NULL;
}

#endif /* HAVE_NGTCP2 */
