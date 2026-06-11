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
 * @brief Establish a QUIC connection to frps and return a bufferevent.
 *
 * This function:
 *  1. Creates a UDP socket and connects to server_addr:port
 *  2. Performs QUIC handshake (ngtcp2 + wolfSSL/OpenSSL)
 *  3. Opens a QUIC stream
 *  4. Returns a bufferevent backed by socketpair <-> QUIC stream relay
 *
 * The returned bufferevent behaves exactly like a TCP bufferevent —
 * existing send_msg_frp_server() / recv_cb() code works unchanged.
 *
 * @param base        libevent base
 * @param server_addr  frps hostname or IP
 * @param port         frps QUIC port (quicBindPort)
 * @return bufferevent, or NULL on failure
 */
struct bufferevent *quic_connect_to_server(struct event_base *base,
					   const char *server_addr,
					   int port);

/**
 * @brief Check if QUIC transport is available (ngtcp2 compiled in).
 * @return 1 if available, 0 otherwise
 */
int quic_transport_available(void);

#endif /* XFRPC_QUIC_CLIENT_TRANSPORT_H */
