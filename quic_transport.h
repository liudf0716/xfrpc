// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * QUIC Transport Layer for XTCP P2P tunnel.
 *
 * Uses ngtcp2 + OpenSSL to establish a reliable, multiplexed
 * connection over the UDP socket obtained after NAT hole-punching.
 *
 * Architecture:
 *   TCP user_conn <-> QUIC stream <-> UDP (hole-punched) <-> peer
 *
 * This replaces the previous raw UDP relay which had no reliability
 * or ordering guarantees.
 */

#ifndef XFRPC_QUIC_TRANSPORT_H
#define XFRPC_QUIC_TRANSPORT_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#include <event2/event.h>
#include <event2/bufferevent.h>

/* Forward declarations */
struct quic_ctx;

/* QUIC stream callback: called when data is received on a stream */
typedef void (*quic_stream_recv_cb)(int64_t stream_id,
				    const uint8_t *data, size_t datalen,
				    void *user_data);

/* QUIC stream callback: called when a stream is closed */
typedef void (*quic_stream_close_cb)(int64_t stream_id,
				     uint64_t app_error_code,
				     void *user_data);

/* QUIC connection callback: called when connection is established */
typedef void (*quic_conn_ready_cb)(void *user_data);

/* QUIC connection callback: called when connection is closed */
typedef void (*quic_conn_close_cb)(uint64_t error_code,
				   void *user_data);

/* QUIC configuration */
struct quic_config {
	const char *alpn;            /* ALPN protocol string, e.g. "frp" */
	int         max_idle_timeout_sec; /* Max idle timeout in seconds */
	int         max_streams;     /* Max concurrent streams */
	int         is_server;       /* 1 = server (client in frp terms), 0 = client (visitor) */
};

/* QUIC stream callbacks */
struct quic_stream_callbacks {
	quic_stream_recv_cb   on_recv;
	quic_stream_close_cb  on_close;
	quic_conn_ready_cb    on_conn_ready;
	quic_conn_close_cb    on_conn_close;
	void                 *user_data;
};

/**
 * @brief Create a QUIC context over an existing UDP socket.
 *
 * The UDP socket must already be hole-punched (connected to peer).
 * This function sets up ngtcp2 + OpenSSL and registers libevent
 * callbacks for the UDP fd.
 *
 * @param base       libevent base
 * @param udp_fd     Hole-punched UDP socket fd
 * @param peer_addr  Peer address (for initial path)
 * @param config     QUIC configuration
 * @param cbs        Stream/connection callbacks
 * @return QUIC context, or NULL on failure
 */
struct quic_ctx *quic_ctx_new(struct event_base *base,
			      int udp_fd,
			      const struct sockaddr_in *peer_addr,
			      const struct quic_config *config,
			      const struct quic_stream_callbacks *cbs);

/**
 * @brief Write data to a QUIC stream.
 *
 * Data is buffered and sent reliably over the QUIC connection.
 * The first call on a client connection opens stream 0.
 *
 * @param qc         QUIC context
 * @param stream_id  Stream ID (-1 for default stream 0)
 * @param data       Data to write
 * @param datalen    Length of data
 * @return 0 on success, -1 on failure
 */
int quic_stream_write(struct quic_ctx *qc, int64_t stream_id,
		      const uint8_t *data, size_t datalen);

/**
 * @brief Write data from an evbuffer to a QUIC stream.
 *
 * Zero-copy friendly: reads directly from the evbuffer.
 *
 * @param qc         QUIC context
 * @param stream_id  Stream ID (-1 for default stream 0)
 * @param buf        evbuffer to read from
 * @return bytes written, or -1 on failure
 */
ssize_t quic_stream_write_evbuf(struct quic_ctx *qc, int64_t stream_id,
				struct evbuffer *buf);

/**
 * @brief Close a QUIC stream gracefully.
 *
 * @param qc         QUIC context
 * @param stream_id  Stream ID to close
 * @param app_error  Application error code (0 = no error)
 * @return 0 on success
 */
int quic_stream_close(struct quic_ctx *qc, int64_t stream_id,
		      uint64_t app_error);

/**
 * @brief Destroy a QUIC context and free all resources.
 *
 * Closes the QUIC connection gracefully, frees OpenSSL and
 * ngtcp2 resources, and removes libevent watchers.
 *
 * @param qc QUIC context to destroy
 */
void quic_ctx_free(struct quic_ctx *qc);

/**
 * @brief Check if the QUIC connection is established and ready.
 *
 * @param qc QUIC context
 * @return true if connected, false otherwise
 */
bool quic_ctx_is_ready(const struct quic_ctx *qc);

#endif /* XFRPC_QUIC_TRANSPORT_H */
