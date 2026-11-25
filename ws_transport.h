// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * WebSocket (ws / wss) transport wrapper for xfrpc using libevent bufferevent_pair.
 */

#ifndef XFRPC_WS_TRANSPORT_H
#define XFRPC_WS_TRANSPORT_H

#include <event2/bufferevent.h>
#include <event2/event.h>

/**
 * @brief Wrap a connected/connecting TCP or TLS bufferevent with RFC 6455 WebSocket framing.
 *
 * Performs HTTP/1.1 Upgrade to "/~!frp" upon underlying connect, then frames all
 * traffic as RFC 6455 masked binary frames.
 *
 * @param base     Event base
 * @param raw_bev  Underlying TCP or TLS bufferevent (ownership transferred)
 * @param host     Host header / SNI name
 * @param port     Server port
 * @param is_wss   1 if wss (TLS), 0 if ws (plaintext)
 * @return App-facing bufferevent (pair[0]), or NULL on error (raw_bev freed).
 */
struct bufferevent *ws_wrap_bev(struct event_base *base,
                                struct bufferevent *raw_bev,
                                const char *host, int port, int is_wss);

#endif /* XFRPC_WS_TRANSPORT_H */
