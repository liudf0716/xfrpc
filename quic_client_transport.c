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

/* Getter functions from tls.c — avoids config.h -> tcpmux.h DATA conflict with wolfSSL */
extern char *tls_get_ca_file(void);
extern char *tls_get_cert_file(void);
extern char *tls_get_key_file(void);

/* Global QUIC connection context — reused for work streams */
static struct quic_client_ctx *g_qc = NULL;

#define QC_MAX_UDP_PAYLOAD   1452
#define QC_HANDSHAKE_TIMEOUT 10
#define QC_MAX_IDLE_SEC      120
#define QC_RELAY_BUF_SIZE    65536

struct quic_client_ctx {
	struct event_base  *base;
	struct event       *udp_read_ev;
	struct event       *timer_ev;
	struct event       *hs_timer_ev;  /* handshake completion poll timer */
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
	int                 handshake_confirmed;
	int                 draining;
	int64_t             stream_id;     /* opened bidi stream for app data */
	ngtcp2_crypto_conn_ref conn_ref;
	quic_handshake_cb   hs_cb;        /* completion callback */
	void               *hs_cb_arg;    /* opaque arg for hs_cb */
	char                server_addr[256];
	int                 server_port;
	uint8_t             wbuf[QC_MAX_UDP_PAYLOAD];

	/* Work stream relays: map stream_id -> socketpair fd */
	struct work_stream_relay {
		int64_t  stream_id;
		int      sp_fd;      /* write end: data from QUIC -> bev */
		struct evbuffer *out_buf;
		struct event *read_ev; /* re-trigger sp_read_cb for partial sends */
	} work_streams[64];
	int work_stream_count;
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
	size_t before = evbuffer_get_length(qc->quic_out_buf);
	int n = evbuffer_write(qc->quic_out_buf, qc->sp_fd);
	debug(LOG_DEBUG, "QUIC client: sp flush %d bytes (buf %zu -> %zu)",
	      n, before, evbuffer_get_length(qc->quic_out_buf));
	if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		debug(LOG_ERR, "QUIC client: sp write err: %s", strerror(errno));
}

static int qc_write_udp(struct quic_client_ctx *qc)
{
	if (qc->draining) return -1;

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
			if (n == NGTCP2_ERR_DRAINING) {
				debug(LOG_DEBUG, "QUIC client: writev_stream: ERR_DRAINING");
				return -1;
			}
			if (n == 0) {
				debug(LOG_DEBUG, "QUIC client: writev_stream returned 0 (nothing to write)");
			} else {
				debug(LOG_ERR, "QUIC client: writev_stream returned %zd: %s",
				      n, ngtcp2_strerror((int)n));
			}
			break;
		}
		debug(LOG_DEBUG, "QUIC client: sending %zd bytes", n);
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

static ngtcp2_conn *qc_get_conn(ngtcp2_crypto_conn_ref *ref)
{
	struct quic_client_ctx *qc =
		(struct quic_client_ctx *)((char *)ref -
			offsetof(struct quic_client_ctx, conn_ref));
	return qc->conn;
}

static int qc_client_initial(ngtcp2_conn *conn, void *ud)
{
	(void)ud;
	debug(LOG_DEBUG, "QUIC client: qc_client_initial called");
	int rv = ngtcp2_crypto_client_initial_cb(conn, ud);
	debug(LOG_DEBUG, "QUIC client: qc_client_initial returned %d", rv);
	return rv;
}

static int qc_recv_crypto(ngtcp2_conn *conn, ngtcp2_encryption_level level,
			  uint64_t off, const uint8_t *data, size_t len,
			  void *ud)
{
	struct quic_client_ctx *qc = ud;
	(void)off;

	/*
	 * BUG FIX: quic-go sends post-handshake TLS data (NewSessionTicket)
	 * as 1RTT CRYPTO frames. We must still pass these to wolfSSL for
	 * proper TLS processing. But we also need to ensure stream 0 is
	 * opened ASAP so that STREAM frames (LoginResp etc.) from the
	 * server can be delivered via recv_stream_data.
	 */
	int rv = ngtcp2_crypto_recv_crypto_data_cb(conn, level, off, data, len, ud);
	int tls_err = ngtcp2_conn_get_tls_error(conn);
	int completed = ngtcp2_conn_get_handshake_completed(conn);
	debug(LOG_DEBUG, "QUIC client: recv_crypto level=%d len=%zu rv=%d completed=%d hs_done=%d tls_err=%d",
	      level, len, rv, completed, qc->handshake_done, tls_err);
	if (rv != 0) {
		debug(LOG_ERR, "QUIC client: crypto_recv_cb failed: rv=%d tls_err=%d", rv, tls_err);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	if (!qc->handshake_done && completed) {
		qc->handshake_done = 1;
		debug(LOG_INFO, "QUIC client: handshake complete (tls_err=%d)", tls_err);
	}
	/* If TLS handshake is done, tell ngtcp2 explicitly */
	if (completed && !qc->handshake_done) {
		ngtcp2_conn_tls_handshake_completed(conn);
	}
	return 0;
}

static int qc_handshake_done(ngtcp2_conn *conn, void *ud)
{
	(void)conn;
	struct quic_client_ctx *qc = ud;
	qc->handshake_done = 1;
	debug(LOG_INFO, "QUIC client: handshake_completed callback fired");
	/* Stream 0 will be opened in handshake_confirmed callback */
	return 0;
}

static int qc_handshake_confirmed(ngtcp2_conn *conn, void *ud)
{
	(void)conn;
	struct quic_client_ctx *qc = ud;
	debug(LOG_INFO, "QUIC client: handshake_confirmed callback fired");
	qc->handshake_confirmed = 1;
	/* Stream 0 will be opened in qc_handshake_timer_cb after the
	 * handshake timer finishes, to ensure quic-go has fully processed
	 * the handshake confirmation before we open streams. */
	return 0;
}

static int qc_recv_stream(ngtcp2_conn *conn, uint32_t flags,
			  int64_t sid, uint64_t off,
			  const uint8_t *data, size_t len,
			  void *ud, void *sud)
{
	struct quic_client_ctx *qc = ud;
	(void)conn; (void)flags; (void)off; (void)sud;

	debug(LOG_DEBUG, "QUIC client: recv_stream_data ENTER sid=%zd len=%zu flags=0x%x",
	      (ssize_t)sid, len, flags);

	/* Handle FIN with no data — peer closed the stream for writing.
	 * Signal EOF to the socketpair so the control code sees it promptly,
	 * rather than waiting for the stream_close callback. */
	if (len == 0 && (flags & NGTCP2_STREAM_DATA_FLAG_FIN)) {
		debug(LOG_INFO, "QUIC client: stream %zd received FIN (no data)", (ssize_t)sid);
		if (sid == qc->stream_id && qc->sp_fd >= 0) {
			debug(LOG_WARNING, "QUIC client: control stream FIN, notifying control code");
			shutdown(qc->sp_fd, SHUT_WR);
		} else {
			for (int i = 0; i < qc->work_stream_count; i++) {
				if (qc->work_streams[i].stream_id == sid) {
					debug(LOG_WARNING, "QUIC client: work stream %zd FIN", (ssize_t)sid);
					if (qc->work_streams[i].read_ev) {
						event_free(qc->work_streams[i].read_ev);
						qc->work_streams[i].read_ev = NULL;
					}
					if (qc->work_streams[i].sp_fd >= 0) {
						close(qc->work_streams[i].sp_fd);
						qc->work_streams[i].sp_fd = -1;
					}
					if (qc->work_streams[i].out_buf) {
						evbuffer_free(qc->work_streams[i].out_buf);
						qc->work_streams[i].out_buf = NULL;
					}
					break;
				}
			}
		}
		return 0;
	}

	if (len <= 0) return 0;

	/* Log first 32 bytes of received data */
	if (len > 0) {
		int show = len < 32 ? (int)len : 32;
		char hex[100];
		for (int i = 0; i < show; i++) snprintf(hex + i*3, 4, "%02x ", data[i]);
		hex[show*3] = 0;
		debug(LOG_DEBUG, "QUIC client: stream %zd recv %zu bytes: [%s]",
		      (ssize_t)sid, len, hex);
	}

	/* Route to work stream relay if not the control stream */
	if (sid != qc->stream_id) {
		for (int i = 0; i < qc->work_stream_count; i++) {
			if (qc->work_streams[i].stream_id == sid &&
			    qc->work_streams[i].sp_fd >= 0) {
				if (qc->work_streams[i].out_buf) {
					size_t before = evbuffer_get_length(qc->work_streams[i].out_buf);
					evbuffer_add(qc->work_streams[i].out_buf, data, len);
					int n = evbuffer_write(qc->work_streams[i].out_buf,
							       qc->work_streams[i].sp_fd);
					size_t after = evbuffer_get_length(qc->work_streams[i].out_buf);
					debug(LOG_DEBUG, "QUIC work stream %zd: relay %zu bytes, wrote %d, "
					      "buf %zu->%zu", (ssize_t)sid, len, n, before, after);
					if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
						debug(LOG_ERR, "QUIC work stream %zd write err: %s",
						      (ssize_t)sid, strerror(errno));
					if (after > 0)
						debug(LOG_WARNING, "QUIC work stream %zd: %zu bytes stuck in out_buf!",
						      (ssize_t)sid, after);
				}
				return 0;
			}
		}
		debug(LOG_WARNING, "QUIC client: data for unknown stream %zd", (ssize_t)sid);
		return 0;
	}

	/* Control stream: write to control socketpair */
	debug(LOG_DEBUG, "QUIC client: stream %zd -> control sp (buf=%zu + %zu)",
	      (ssize_t)sid, evbuffer_get_length(qc->quic_out_buf), len);
	evbuffer_add(qc->quic_out_buf, data, len);
	qc_flush_sp(qc);
	debug(LOG_DEBUG, "QUIC client: control sp flushed (buf=%zu)",
	      evbuffer_get_length(qc->quic_out_buf));
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
	(void)c; (void)ud;
	debug(LOG_DEBUG, "QUIC client: stream_open sid=%zd", (ssize_t)sid);
	return 0;
}

static int qc_stream_close(ngtcp2_conn *c, uint32_t flags, int64_t sid,
			   uint64_t ec, void *ud, void *sud)
{
	struct quic_client_ctx *qc = ud;
	(void)c; (void)sud;

	debug(LOG_INFO, "QUIC client: stream_close sid=%zd flags=0x%x ec=%llu",
	      (ssize_t)sid, flags, (unsigned long long)ec);

	if (!qc) return 0;

	/* If the control stream is closed by the peer, close the write end
	 * of the socketpair so the libevent control code sees EOF and can
	 * trigger reconnection. Without this, the control code blocks forever
	 * on the socketpair read. */
	if (sid == qc->stream_id) {
		debug(LOG_WARNING, "QUIC client: control stream %zd closed by peer, "
		      "notifying control code", (ssize_t)sid);
		if (qc->sp_fd >= 0) {
			/* Shutdown the write side so the bev read end gets EOF.
			 * We use shutdown(SHUT_WR) rather than close() because
			 * the bufferevent owns the other end of the socketpair. */
			shutdown(qc->sp_fd, SHUT_WR);
		}
		return 0;
	}

	/* If a work stream is closed by the peer, close its socketpair end */
	for (int i = 0; i < qc->work_stream_count; i++) {
		if (qc->work_streams[i].stream_id == sid) {
			debug(LOG_WARNING, "QUIC client: work stream %zd closed by peer",
			      (ssize_t)sid);
			if (qc->work_streams[i].read_ev) {
				event_free(qc->work_streams[i].read_ev);
				qc->work_streams[i].read_ev = NULL;
			}
			if (qc->work_streams[i].sp_fd >= 0) {
				close(qc->work_streams[i].sp_fd);
				qc->work_streams[i].sp_fd = -1;
			}
			if (qc->work_streams[i].out_buf) {
				evbuffer_free(qc->work_streams[i].out_buf);
				qc->work_streams[i].out_buf = NULL;
			}
			break;
		}
	}
	return 0;
}

static void qc_rand(uint8_t *dest, size_t len,
			 const ngtcp2_rand_ctx *ctx)
{
	(void)ctx;
	RAND_bytes(dest, (int)len);
}

static int qc_get_new_cid(ngtcp2_conn *c, ngtcp2_cid *cid,
			  uint8_t *token, size_t cidlen, void *ud)
{
	(void)c; (void)ud;
	RAND_bytes(cid->data, cidlen);
	cid->datalen = (uint8_t)cidlen;
	if (token) RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
	return 0;
}

static int qc_update_key(ngtcp2_conn *c,
			  uint8_t *rx_secret, uint8_t *tx_secret,
			  ngtcp2_crypto_aead_ctx *rx_aead_ctx,
			  uint8_t *rx_iv,
			  ngtcp2_crypto_aead_ctx *tx_aead_ctx,
			  uint8_t *tx_iv,
			  const uint8_t *cur_rx_secret,
			  const uint8_t *cur_tx_secret,
			  size_t secretlen, void *ud)
{
	(void)ud;
	return ngtcp2_crypto_update_key_cb(c, rx_secret, tx_secret,
					   rx_aead_ctx, rx_iv,
					   tx_aead_ctx, tx_iv,
					   cur_rx_secret, cur_tx_secret,
					   secretlen, ud);
}

static int qc_path_challenge(ngtcp2_conn *c, uint8_t *data, void *ud)
{
	(void)c; (void)ud;
	RAND_bytes(data, 8);
	return 0;
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
	.handshake_confirmed      = qc_handshake_confirmed,
	.encrypt                  = ngtcp2_crypto_encrypt_cb,
	.decrypt                  = ngtcp2_crypto_decrypt_cb,
	.hp_mask                  = ngtcp2_crypto_hp_mask_cb,
	.recv_stream_data         = qc_recv_stream,
	.acked_stream_data_offset = qc_acked,
	.recv_retry               = ngtcp2_crypto_recv_retry_cb,
	.get_new_connection_id    = qc_get_new_cid,
	.update_key               = qc_update_key,
	.get_path_challenge_data  = qc_path_challenge,
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

	/* Log first 32 bytes of received packet for full structure analysis */
	char hex[128] = {0};
	int hexlen = n < 32 ? (int)n : 32;
	for (int i = 0; i < hexlen; i++)
		snprintf(hex + i * 3, 4, "%02x ", buf[i]);
	debug(LOG_DEBUG, "QUIC client: recv %zd bytes: [%s]", n, hex);

	struct sockaddr_in la;
	socklen_t lal = sizeof(la);
	getsockname(fd, (struct sockaddr *)&la, &lal);

	ngtcp2_path_storage path_st;
	ngtcp2_path_storage_init(&path_st,
				 (struct sockaddr *)&la, lal,
				 (struct sockaddr *)&pa, pal, NULL);

	int rv = ngtcp2_conn_read_pkt(qc->conn, &path_st.path, NULL,
				      buf, (size_t)n, qc_ts());
	int tls_err = ngtcp2_conn_get_tls_error(qc->conn);
	debug(LOG_DEBUG, "QUIC client: read_pkt returned %d (hs_done=%d, confirmed=%d, stream_id=%zd, draining=%d, tls_err=%d)",
	      rv, qc->handshake_done, qc->handshake_confirmed,
	      (ssize_t)qc->stream_id, qc->draining, tls_err);
	if (rv != 0) {
		if (ngtcp2_err_is_fatal(rv)) {
			debug(LOG_ERR, "QUIC client: fatal error in read_pkt: %s (%d), tls_err=%d",
			      ngtcp2_strerror(rv), rv, tls_err);
			qc->draining = 1;
			/* Remove UDP read event to prevent CPU spin on draining connection */
			if (qc->udp_read_ev) {
				event_del(qc->udp_read_ev);
			}
			/* Notify caller of failure so reconnect can happen */
			if (qc->hs_cb && !qc->handshake_confirmed) {
				qc->hs_cb(NULL, qc->hs_cb_arg);
			}
			return;
		}
		debug(LOG_DEBUG, "QUIC client: read_pkt non-fatal: %s (%d)",
		      ngtcp2_strerror(rv), rv);
	}
	qc_flush_sp(qc);
	qc_write_udp(qc);
}

static void qc_sp_read_cb(evutil_socket_t fd, short what, void *arg)
{
	struct quic_client_ctx *qc = arg;
	(void)what;
	if (qc->draining) return;

	uint8_t buf[QC_RELAY_BUF_SIZE];
	ssize_t n = read(fd, buf, sizeof(buf));
	if (n <= 0) { if (n < 0 && errno == EAGAIN) return; return; }

	debug(LOG_DEBUG, "QUIC client: sp_read_cb: n=%zd stream_id=%zd",
	      n, (ssize_t)qc->stream_id);

	ngtcp2_vec dv = { .base = buf, .len = (size_t)n };
	ngtcp2_path_storage ps;
	struct sockaddr_in la;
	socklen_t al = sizeof(la);
	getsockname(qc->udp_fd, (struct sockaddr *)&la, &al);
	ngtcp2_path_storage_init(&ps, (struct sockaddr *)&la, al, NULL, 0, NULL);
	ngtcp2_pkt_info pi;
	memset(&pi, 0, sizeof(pi));

	ngtcp2_ssize nw = ngtcp2_conn_writev_stream(
			qc->conn, &ps.path, &pi,
			qc->wbuf, sizeof(qc->wbuf), NULL,
			NGTCP2_WRITE_STREAM_FLAG_NONE,
			qc->stream_id, &dv, 1, qc_ts());
	debug(LOG_DEBUG, "QUIC client: sp_writev: nw=%zd stream_id=%zd",
	      (ssize_t)nw, (ssize_t)qc->stream_id);
	if (nw == NGTCP2_ERR_DRAINING) {
		qc->draining = 1;
		debug(LOG_ERR, "QUIC client: connection draining in sp_read_cb");
		/* Stop events to prevent CPU spin */
		if (qc->udp_read_ev) event_del(qc->udp_read_ev);
		if (qc->sp_read_ev) event_del(qc->sp_read_ev);
		return;
	}
	if (nw < 0) {
		debug(LOG_ERR, "QUIC client: writev_stream in sp_read_cb: %s",
		      ngtcp2_strerror((int)nw));
		return;
	}
	/* Send the packet generated by writev_stream immediately.
	 * qc_write_udp() overwrites qc->wbuf, so the packet must be sent first
	 * to avoid losing stream data. */
	if (nw > 0) {
		ssize_t sent = send(qc->udp_fd, qc->wbuf, (size_t)nw, 0);
		(void)sent;
	}
	qc_write_udp(qc);
}

static void qc_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	struct quic_client_ctx *qc = arg;
	(void)fd; (void)what;
	if (qc->draining) return;  /* Already draining — do nothing */
	int rv = ngtcp2_conn_handle_expiry(qc->conn, qc_ts());
	if (rv != 0) {
		debug(LOG_DEBUG, "QUIC client: timer expiry returned %d (%s), "
		      "hs_done=%d confirmed=%d",
		      rv, ngtcp2_strerror(rv),
		      qc->handshake_done, qc->handshake_confirmed);
		/* Only drain for truly fatal errors; let handshake timer
		 * handle transient issues during the handshake phase. */
		if (ngtcp2_err_is_fatal(rv) &&
		    (rv != NGTCP2_ERR_HANDSHAKE_TIMEOUT || qc->handshake_done)) {
			qc->draining = 1;
			/* Stop UDP read to prevent CPU spin */
			if (qc->udp_read_ev) event_del(qc->udp_read_ev);
			/* Notify caller if handshake never completed */
			if (qc->hs_cb && !qc->handshake_confirmed) {
				qc->hs_cb(NULL, qc->hs_cb_arg);
			}
			return;
		}
		/* Transient or handshake-timeout during handshake phase —
		 * the handshake timer will handle retransmission/retry. */
	}
	qc_write_udp(qc);
}

static void qc_free(struct quic_client_ctx *qc)
{
	if (!qc) return;
	/* Clear global pointer if it points to this context */
	if (g_qc == qc) g_qc = NULL;
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

/* Forward declaration */
static void qc_handshake_timer_cb(evutil_socket_t fd, short what, void *arg);

int quic_connect_to_server(struct event_base *base,
			   const char *server_addr, int port,
			   quic_handshake_cb cb, void *cb_arg)
{
	if (!base || !server_addr || port <= 0) return -1;

	struct quic_client_ctx *qc = calloc(1, sizeof(*qc));
	if (!qc) return -1;
	qc->udp_fd = qc->sp_fd = qc->bev_fd = -1;
	qc->stream_id = -1;  /* not yet opened */

	/* socketpair */
	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp) < 0) {
		free(qc); return -1;
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
	if (!qc->ssl_ctx) goto fail;
	if (ngtcp2_crypto_wolfssl_configure_client_context(qc->ssl_ctx) != 0) {
		debug(LOG_ERR, "QUIC client: wolfssl configure failed");
		goto fail;
	}
#else
	qc->ssl_ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(qc->ssl_ctx, TLS1_3_VERSION);
#endif
	if (!qc->ssl_ctx) goto fail;

	/* Load TLS certificates from config (for mTLS support).
	 * Must use the same SSL API as the SSL_CTX was created with. */
	{
		char *ca_file = tls_get_ca_file();
		char *cert_file = tls_get_cert_file();
		char *key_file = tls_get_key_file();
		if (ca_file) {
			if (SSL_CTX_load_verify_locations(qc->ssl_ctx, ca_file, NULL) != 1)
				debug(LOG_ERR, "QUIC client: failed to load CA: %s", ca_file);
			else {
				SSL_CTX_set_verify(qc->ssl_ctx, SSL_VERIFY_PEER, NULL);
				debug(LOG_INFO, "QUIC client: CA loaded: %s", ca_file);
			}
		}
		if (cert_file) {
			if (SSL_CTX_use_certificate_chain_file(qc->ssl_ctx, cert_file) != 1)
				debug(LOG_ERR, "QUIC client: failed to load cert: %s", cert_file);
			else
				debug(LOG_INFO, "QUIC client: cert loaded: %s", cert_file);
		}
		if (key_file) {
			if (SSL_CTX_use_PrivateKey_file(qc->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1)
				debug(LOG_ERR, "QUIC client: failed to load key: %s", key_file);
			else
				debug(LOG_INFO, "QUIC client: key loaded: %s", key_file);
		}
	}

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
	/* settings.initial_ts = 0; -- use default (0 = epoch, ngtcp2 handles this) */
	settings.max_tx_udp_payload_size = QC_MAX_UDP_PAYLOAD;
	/* Use ngtcp2 default handshake_timeout (UINT64_MAX = no timeout) */

	ngtcp2_transport_params tp;
	ngtcp2_transport_params_default(&tp);
	tp.initial_max_data = 1024 * 1024;
	tp.initial_max_stream_data_bidi_local = 512 * 1024;
	tp.initial_max_stream_data_bidi_remote = 512 * 1024;
	tp.initial_max_streams_bidi = 100;
	tp.initial_max_streams_uni = 10;
	tp.max_idle_timeout = (uint64_t)QC_MAX_IDLE_SEC * NGTCP2_SECONDS;

	int rv = ngtcp2_conn_client_new(&qc->conn, &qc->dcid, &qc->scid,
					&qc->path, NGTCP2_PROTO_VER_V1,
					&qc_cbs, &settings, &tp, NULL, qc);
	if (rv != 0) {
		debug(LOG_ERR, "QUIC client: ngtcp2 err: %s", ngtcp2_strerror(rv));
		goto fail;
	}
	ngtcp2_conn_set_tls_native_handle(qc->conn, qc->ssl);

	debug(LOG_DEBUG, "QUIC client: callbacks registered: recv_stream_data=%p",
	      (void *)qc_cbs.recv_stream_data);

	/* Set up conn_ref for wolfssl QUIC crypto callbacks */
	qc->conn_ref.get_conn = qc_get_conn;
	qc->conn_ref.user_data = qc;
#ifdef USE_NGTCP2_WOLFSSL
	wolfSSL_set_app_data(qc->ssl, &qc->conn_ref);
#endif

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
	int wv = qc_write_udp(qc);
	debug(LOG_INFO, "QUIC client: qc_write_udp returned %d", wv);
	event_add(qc->udp_read_ev, NULL);
	/* Do NOT add sp_read_ev yet — prevent 1-RTT data before handshake done */

	/* Save callback and server info for async completion */
	qc->hs_cb = cb;
	qc->hs_cb_arg = cb_arg;
	qc->server_port = port;
	strncpy(qc->server_addr, server_addr, sizeof(qc->server_addr) - 1);
	qc->server_addr[sizeof(qc->server_addr) - 1] = '\0';

	/* Register a 10 ms repeating timer to poll for handshake completion.
	 * This avoids calling event_base_loop() (which would be reentrant
	 * when called from within an existing event callback). */
	qc->hs_timer_ev = evtimer_new(base, qc_handshake_timer_cb, qc);
	if (!qc->hs_timer_ev) goto fail;
	struct timeval hs_interval = { 0, 10000 }; /* 10 ms */
	evtimer_add(qc->hs_timer_ev, &hs_interval);

	/* Handshake will complete asynchronously via timer + UDP read callbacks.
	 * The caller will be notified through the hs_cb callback. */
	return 0;

fail:
	if (qc->bev_fd >= 0) close(qc->bev_fd);
	qc_free(qc);
	return -1;
}

/* ============================================================
 * Handshake completion timer — runs inside the event loop,
 * polls ngtcp2 for handshake completion.
 * ============================================================ */
static void qc_handshake_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd; (void)what;
	struct quic_client_ctx *qc = arg;
	struct event_base *base = qc->base;

	/* Drive ngtcp2 state machine */
	qc_write_udp(qc);

	if (qc->draining) {
		/* Only treat draining as permanent failure when the handshake is
		 * fully confirmed.  ngtcp2 can enter a transient draining state
		 * between handshake_done and handshake_confirmed — in that window
		 * the connection is still recoverable. */
		if (qc->handshake_confirmed) {
			debug(LOG_ERR, "QUIC client: connection draining after handshake confirmed");
			if (qc->hs_cb) qc->hs_cb(NULL, qc->hs_cb_arg);
			qc_free(qc);
			return;
		}
		/* Transient draining — reset and re-arm timer */
		debug(LOG_DEBUG, "QUIC client: transient draining (confirmed=%d, done=%d), resetting",
		      qc->handshake_confirmed, qc->handshake_done);
		qc->draining = 0;
		struct timeval hs_interval = { 0, 10000 };
		evtimer_add(qc->hs_timer_ev, &hs_interval);
		return;
	}

	if (!qc->handshake_done) {
		/* Not done yet — re-arm timer */
		struct timeval hs_interval = { 0, 10000 };
		evtimer_add(qc->hs_timer_ev, &hs_interval);
		return;
	}

	/* Wait for handshake_confirmed before proceeding.
	 * quic-go v0.55.0 may not accept stream data until the handshake
	 * is fully confirmed (not just completed). */
	if (!qc->handshake_confirmed) {
		debug(LOG_DEBUG, "QUIC client: handshake done but not confirmed, waiting...");
		struct timeval hs_interval = { 0, 10000 };
		evtimer_add(qc->hs_timer_ev, &hs_interval);
		return;
	}

	/* Handshake completed and confirmed — stop the handshake timer */
	if (qc->hs_timer_ev) {
		evtimer_del(qc->hs_timer_ev);
		event_free(qc->hs_timer_ev);
		qc->hs_timer_ev = NULL;
	}

	debug(LOG_INFO, "QUIC client: connected to %s:%d", qc->server_addr, qc->server_port);

	/* Open the first client-initiated bidirectional stream (stream 0).
	 * This may already have been opened early in recv_crypto — if so, skip. */
	if (qc->stream_id < 0) {
		int64_t sid;
		int rv = ngtcp2_conn_open_bidi_stream(qc->conn, &sid, NULL);
		if (rv != 0) {
			debug(LOG_ERR, "QUIC client: failed to open bidi stream: %s",
			      ngtcp2_strerror(rv));
			if (qc->hs_cb) qc->hs_cb(NULL, qc->hs_cb_arg);
			qc_free(qc);
			return;
		}
		qc->stream_id = sid;
		debug(LOG_INFO, "QUIC client: opened bidi stream %zd", (ssize_t)sid);
	} else {
		debug(LOG_INFO, "QUIC client: bidi stream %zd already opened (early)",
		      (ssize_t)qc->stream_id);
	}

	qc->draining = 0;
	g_qc = qc;

	/* Enable application data flow */
	event_add(qc->sp_read_ev, NULL);

	/* Create the bufferevent for the caller */
	struct bufferevent *bev = bufferevent_socket_new(base, qc->bev_fd,
						BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		debug(LOG_ERR, "QUIC client: failed to create bev");
		if (qc->hs_cb) qc->hs_cb(NULL, qc->hs_cb_arg);
		qc_free(qc);
		return;
	}
	qc->bev_fd = -1;

	/* Notify caller */
	if (qc->hs_cb) qc->hs_cb(bev, qc->hs_cb_arg);
}

static void qc_work_sp_read_cb(evutil_socket_t fd, short what, void *arg)
{
	struct work_stream_relay *relay = arg;
	struct quic_client_ctx *qc = g_qc;
	(void)what;
	if (!qc || qc->draining) return;

	uint8_t buf[QC_RELAY_BUF_SIZE];
	const uint8_t *send_ptr;
	size_t send_len;

	/* If there's leftover data from a previous partial send, send that first */
	if (relay->out_buf && evbuffer_get_length(relay->out_buf) > 0) {
		/* Append any new data from sp[0] */
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n > 0) evbuffer_add(relay->out_buf, buf, (size_t)n);
		send_len = evbuffer_get_length(relay->out_buf);
		if (send_len == 0) return;
		struct evbuffer_iovec iov;
		if (evbuffer_peek(relay->out_buf, send_len, NULL, &iov, 1) < 1) return;
		send_ptr = iov.iov_base;
	} else {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n <= 0) { if (n < 0 && errno == EAGAIN) return; return; }
		send_ptr = buf;
		send_len = (size_t)n;
	}

	debug(LOG_DEBUG, "QUIC work sp_read_cb: stream %zd sending %zu bytes",
	      (ssize_t)relay->stream_id, send_len);

	ngtcp2_vec dv = { .base = (uint8_t *)send_ptr, .len = send_len };
	ngtcp2_path_storage ps;
	struct sockaddr_in la;
	socklen_t al = sizeof(la);
	getsockname(qc->udp_fd, (struct sockaddr *)&la, &al);
	ngtcp2_path_storage_init(&ps, (struct sockaddr *)&la, al, NULL, 0, NULL);
	ngtcp2_pkt_info pi;
	memset(&pi, 0, sizeof(pi));

	ngtcp2_ssize pdatalen = 0;
	ngtcp2_ssize nw = ngtcp2_conn_writev_stream(
			qc->conn, &ps.path, &pi,
			qc->wbuf, sizeof(qc->wbuf), &pdatalen,
			NGTCP2_WRITE_STREAM_FLAG_NONE,
			relay->stream_id, &dv, 1, qc_ts());
	if (nw == NGTCP2_ERR_DRAINING) {
		qc->draining = 1;
		debug(LOG_ERR, "QUIC work stream: connection draining");
		return;
	}
	if (nw < 0) {
		debug(LOG_ERR, "QUIC work stream: writev_stream: %s",
		      ngtcp2_strerror((int)nw));
		return;
	}
	if (nw > 0) {
		send(qc->udp_fd, qc->wbuf, (size_t)nw, 0);
	}
	qc_write_udp(qc);

	/* Handle partial consumption by ngtcp2 */
	size_t consumed = (pdatalen >= 0) ? (size_t)pdatalen : send_len;
	if (relay->out_buf && evbuffer_get_length(relay->out_buf) > 0) {
		/* Drain consumed bytes from out_buf */
		evbuffer_drain(relay->out_buf, consumed);
		/* If data remains, re-trigger to flush */
		if (evbuffer_get_length(relay->out_buf) > 0 && relay->read_ev)
			event_active(relay->read_ev, EV_READ, 0);
	} else if (consumed < send_len) {
		/* Stash unconsumed data in out_buf */
		size_t leftover = send_len - consumed;
		debug(LOG_DEBUG, "QUIC work stream %zd: partial send %zu/%zu, "
		      "%zu bytes stashed", (ssize_t)relay->stream_id,
		      consumed, send_len, leftover);
		if (!relay->out_buf) relay->out_buf = evbuffer_new();
		evbuffer_add(relay->out_buf, send_ptr + consumed, leftover);
		if (relay->read_ev) event_active(relay->read_ev, EV_READ, 0);
	}
}

struct bufferevent *quic_open_work_stream(struct event_base *base)
{
	if (!g_qc || g_qc->draining || !base) return NULL;
	struct quic_client_ctx *qc = g_qc;

	/* Open a new bidirectional stream */
	int64_t sid;
	int rv = ngtcp2_conn_open_bidi_stream(qc->conn, &sid, NULL);
	if (rv != 0) {
		debug(LOG_ERR, "QUIC: failed to open work stream: %s",
		      ngtcp2_strerror(rv));
		return NULL;
	}

	/* Create socketpair for this stream */
	int sp[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp) < 0) {
		debug(LOG_ERR, "QUIC: socketpair failed: %s", strerror(errno));
		return NULL;
	}

	/* Register relay */
	if (qc->work_stream_count >= 64) {
		debug(LOG_ERR, "QUIC: too many work streams");
		close(sp[0]); close(sp[1]);
		return NULL;
	}
	struct work_stream_relay *relay = &qc->work_streams[qc->work_stream_count++];
	relay->stream_id = sid;
	relay->sp_fd = sp[0];
	relay->out_buf = evbuffer_new();

	/* Set up event to read from bev side and send via QUIC */
	struct event *sp_ev = event_new(base, sp[0], EV_READ|EV_PERSIST,
					qc_work_sp_read_cb, relay);
	if (!sp_ev) {
		close(sp[0]); close(sp[1]);
		evbuffer_free(relay->out_buf);
		qc->work_stream_count--;
		return NULL;
	}
	relay->read_ev = sp_ev;
	event_add(sp_ev, NULL);

	debug(LOG_INFO, "QUIC: opened work stream %zd", (ssize_t)sid);

	/* Return bufferevent from the other end of the socketpair */
	struct bufferevent *bev = bufferevent_socket_new(base, sp[1],
							BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		event_free(sp_ev);
		evbuffer_free(relay->out_buf);
		close(sp[0]); close(sp[1]);
		qc->work_stream_count--;
		return NULL;
	}
	return bev;
}

int quic_work_stream_send_initial(const void *data, size_t len)
{
	if (!g_qc || g_qc->draining || !data || len == 0) return -1;
	struct quic_client_ctx *qc = g_qc;

	if (qc->work_stream_count <= 0) return -1;
	struct work_stream_relay *relay =
		&qc->work_streams[qc->work_stream_count - 1];

	ngtcp2_vec dv = { .base = (uint8_t *)data, .len = len };
	ngtcp2_path_storage ps;
	struct sockaddr_in la;
	socklen_t al = sizeof(la);
	getsockname(qc->udp_fd, (struct sockaddr *)&la, &al);
	ngtcp2_path_storage_init(&ps, (struct sockaddr *)&la, al, NULL, 0, NULL);
	ngtcp2_pkt_info pi;
	memset(&pi, 0, sizeof(pi));

	ngtcp2_ssize nw = ngtcp2_conn_writev_stream(
			qc->conn, &ps.path, &pi,
			qc->wbuf, sizeof(qc->wbuf), NULL,
			NGTCP2_WRITE_STREAM_FLAG_NONE,
			relay->stream_id, &dv, 1, qc_ts());
	if (nw <= 0) {
		debug(LOG_ERR, "QUIC work stream send_initial: writev_stream returned %zd (%s)",
		      (ssize_t)nw, nw < 0 ? ngtcp2_strerror((int)nw) : "nothing to write");
		return -1;
	}
	ssize_t sent = send(qc->udp_fd, qc->wbuf, (size_t)nw, 0);
	if (sent < 0) {
		debug(LOG_ERR, "QUIC work stream send_initial: send: %s", strerror(errno));
		return -1;
	}
	debug(LOG_DEBUG, "QUIC work stream %zd: sent %zd initial bytes",
	      (ssize_t)relay->stream_id, (ssize_t)len);
	qc_write_udp(qc);
	return 0;
}

void quic_transport_reset(void)
{
	if (g_qc) {
		debug(LOG_DEBUG, "QUIC: resetting global connection context");
		struct quic_client_ctx *qc = g_qc;
		g_qc = NULL;
		/* Mark as draining so callbacks stop firing. */
		qc->draining = 1;
		if (qc->udp_read_ev) event_del(qc->udp_read_ev);
		if (qc->sp_read_ev) event_del(qc->sp_read_ev);
		if (qc->hs_timer_ev) {
			evtimer_del(qc->hs_timer_ev);
			event_free(qc->hs_timer_ev);
			qc->hs_timer_ev = NULL;
		}
		/* Clean up work stream relays to avoid fd/evbuffer leaks */
		for (int i = 0; i < qc->work_stream_count; i++) {
			if (qc->work_streams[i].sp_fd >= 0) {
				close(qc->work_streams[i].sp_fd);
				qc->work_streams[i].sp_fd = -1;
			}
			if (qc->work_streams[i].out_buf) {
				evbuffer_free(qc->work_streams[i].out_buf);
				qc->work_streams[i].out_buf = NULL;
			}
		}
		qc->work_stream_count = 0;
	}
}

#else /* !HAVE_NGTCP2 */

#include "quic_client_transport.h"
#include "debug.h"
int quic_transport_available(void) { return 0; }
int quic_connect_to_server(struct event_base *b,
			   const char *a, int p,
			   quic_handshake_cb cb, void *cb_arg)
{
	(void)b; (void)a; (void)p; (void)cb; (void)cb_arg;
	debug(LOG_ERR, "QUIC not compiled in");
	return -1;
}
struct bufferevent *quic_open_work_stream(struct event_base *b)
{
	(void)b;
	debug(LOG_ERR, "QUIC not compiled in");
	return NULL;
}

#endif /* HAVE_NGTCP2 */
