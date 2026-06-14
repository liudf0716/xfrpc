// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * QUIC Client Transport — connects xfrpc to frps over QUIC (ngtcp2).
 *
 * Returns a libevent bufferevent backed by a QUIC stream, so all existing
 * xfrpc code (msg.c, control.c, login.c, etc.) works unchanged.
 *
 * Architecture:
 *   xfrpc code  <-->  bufferevent  <-->  socketpair  <-->  QUIC stream
 *                                              ^
 *                                              |
 *                                    quic_client_bev_cb() drives I/O
 */

#ifndef XFRPC_QUIC_CLIENT_TRANSPORT_H
#define XFRPC_QUIC_CLIENT_TRANSPORT_H

#include <event2/event.h>
#include <event2/bufferevent.h>

/**
 * @brief Callback invoked when QUIC handshake completes (or fails).
 *
 * @param bev  bufferevent on success, NULL on failure
 * @param arg  user-provided opaque pointer
 */
typedef void (*quic_handshake_cb)(struct bufferevent *bev, void *arg);

/**
 * @brief Start an async QUIC connection to frps.
 *
 * This function is fully async — it never calls event_base_loop().
 * It registers UDP read + timer events on @p base and returns
 * immediately.  The existing event loop drives the QUIC handshake;
 * when it completes, @p cb is invoked with the resulting bev.
 *
 * @param base         libevent base (must already be running or about to dispatch)
 * @param server_addr  frps hostname or IP
 * @param port         frps QUIC port (quicBindPort)
 * @param cb           completion callback (may be NULL for fire-and-forget)
 * @param arg          opaque pointer forwarded to @p cb
 * @return 0 on success (handshake started), -1 on immediate failure
 */
int quic_connect_to_server(struct event_base *base,
			   const char *server_addr,
			   int port,
			   quic_handshake_cb cb,
			   void *arg);

/**
 * @brief Check if QUIC transport is available (ngtcp2 compiled in).
 * @return 1 if available, 0 otherwise
 */
int quic_transport_available(void);

/**
 * @brief Open a new QUIC stream on the existing connection.
 *
 * Used for work connections that share the same QUIC connection as the
 * control connection. Returns a bufferevent backed by socketpair <-> QUIC stream.
 *
 * @param base  libevent base
 * @return bufferevent, or NULL on failure
 */
struct bufferevent *quic_open_work_stream(struct event_base *base);

/**
 * @brief Send initial data synchronously on the most recently opened work stream.
 *
 * Writes @p data directly to the QUIC wire via ngtcp2, bypassing the
 * socketpair/event-loop.  This is needed because frps may accept the
 * QUIC stream and then immediately FIN it if no STREAM data arrives
 * before the next event-loop pass.
 *
 * @param data  payload to send (e.g. the marshalled NewWorkConn message)
 * @param len   payload length
 * @return 0 on success, -1 on failure
 */
int quic_work_stream_send_initial(const void *data, size_t len);

/**
 * @brief Reset QUIC connection state for clean reconnection.
 */
void quic_transport_reset(void);

#endif /* XFRPC_QUIC_CLIENT_TRANSPORT_H */
