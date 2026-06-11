// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * XTCP Client - P2P tunnel via NAT hole punching (client/proxy side).
 *
 * Flow:
 *   1. Server sends StartWorkConn for XTCP proxy
 *   2. Client does STUN discovery + NAT classification
 *   3. Client sends NatHoleClient to server with STUN results
 *   4. Server responds with NatHoleResp (peer addresses + behavior)
 *   5. Client does UDP hole-punch with encrypted NatHoleSid packets
 *   6. After success, client connects to local service and relays
 */

#ifndef XFRPC_XTCP_CLIENT_H
#define XFRPC_XTCP_CLIENT_H

#include <event2/event.h>
#include <event2/bufferevent.h>

#include "client.h"

/**
 * @brief Start the XTCP client flow for a proxy service.
 *
 * Called from handle_type_start_work_conn() when the proxy type is "xtcp".
 * Performs STUN discovery, sends NatHoleClient, waits for NatHoleResp,
 * does UDP hole-punching, and starts relaying local service data.
 *
 * @param base   Event base
 * @param client The proxy client (from StartWorkConn)
 */
void xtcp_client_run(struct event_base *base, struct proxy_client *client);

/**
 * @brief Handle a NatHoleResp message for client-side XTCP sessions.
 *
 * Called from control.c when TypeNatHoleResp is received.
 * Dispatches to the matching client session by transaction_id.
 *
 * @param json_str The NatHoleResp JSON string
 * @return 1 if handled by client session, 0 if not matched
 */
int xtcp_client_handle_nat_hole_resp(const char *json_str);

/**
 * @brief Cleanup all XTCP client sessions (call on shutdown)
 */
void cleanup_xtcp_clients(void);

#endif /* XFRPC_XTCP_CLIENT_H */
