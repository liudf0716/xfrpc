// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_HEALTH_CHECK_H
#define XFRPC_HEALTH_CHECK_H

#include <event2/event.h>
#include <event2/bufferevent.h>

#include "client.h"

/**
 * @brief Health check result callback.
 *
 * Called when a health check completes (success or failure).
 *
 * @param ps       The proxy service being checked
 * @param healthy  1 if healthy, 0 if unhealthy
 * @param ctx      User context (unused)
 */
typedef void (*health_check_cb_t)(struct proxy_service *ps, int healthy, void *ctx);

/**
 * @brief Start health checks for all proxy services that have health_check_type set.
 *
 * For each proxy with health check configured, creates a periodic timer
 * that performs TCP or HTTP checks against the local service.
 *
 * @param base     Event base for timers and connections
 * @param callback Called on each health check result transition
 * @param ctx      User context passed to callback
 */
void health_check_start_all(struct event_base *base, health_check_cb_t callback, void *ctx);

/**
 * @brief Stop and free all health check timers and state.
 *
 * Call this before reloading configuration or shutting down.
 */
void health_check_stop_all(void);

/**
 * @brief Check if a specific proxy service is currently healthy.
 *
 * @param proxy_name Name of the proxy service
 * @return 1 if healthy (or no health check configured), 0 if unhealthy
 */
int health_check_is_healthy(const char *proxy_name);

/**
 * @brief Get the number of active health checks.
 *
 * @return Number of proxies currently being health-checked
 */
int health_check_count(void);

#endif /* XFRPC_HEALTH_CHECK_H */
