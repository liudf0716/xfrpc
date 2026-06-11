// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * XTCP Visitor - P2P tunnel via NAT hole punching.
 *
 * Flow:
 *   1. PreCheck  — verify XTCP proxy exists on server
 *   2. Prepare   — STUN discovery + NAT classification
 *   3. Exchange  — send NatHoleVisitor, receive NatHoleResp
 *   4. MakeHole  — UDP hole-punch with encrypted NatHoleSid packets
 *   5. Tunnel    — relay TCP data over the P2P UDP tunnel
 */

#ifndef XFRPC_XTCP_VISITOR_H
#define XFRPC_XTCP_VISITOR_H

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include "visitor.h"

/**
 * @brief Run the XTCP visitor for a given visitor session.
 *
 * Called from visitor_accept_cb() when the visitor type is "xtcp".
 * Performs the full NAT hole-punching flow and starts relaying data.
 *
 * @param base      Event base
 * @param vi        Visitor instance (contains config)
 * @param user_bev  Bufferevent for the local TCP connection from the user
 */
void xtcp_visitor_run(struct event_base *base,
		      struct visitor_instance *vi,
		      struct bufferevent *user_bev);

/**
 * @brief Initialize XTCP visitors (called at startup)
 *
 * Performs STUN discovery for all configured XTCP visitors
 * and caches the results for later use.
 *
 * @param base Event base
 */
void init_xtcp_visitors(struct event_base *base);

/**
 * @brief Close any unconsumed STUN sockets in the cache.
 *
 * Call on shutdown to prevent fd leaks.
 */
void cleanup_xtcp_stun_cache(void);

/**
 * @brief Handle a NatHoleResp message received from the server.
 *
 * Called from control.c when TypeNatHoleResp is received.
 * Parses the response and dispatches to the appropriate XTCP session.
 *
 * @param json_str The JSON payload of the NatHoleResp message
 */
void xtcp_handle_nat_hole_resp_msg(const char *json_str);

#endif /* XFRPC_XTCP_VISITOR_H */
