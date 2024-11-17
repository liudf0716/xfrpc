
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_TCP_REDIR_H
#define XFRPC_TCP_REDIR_H

#include "proxy.h"

/**
 * Starts the TCP redirection service
 * @param proxy Pointer to proxy service configuration
 */
void start_tcp_redir_service(struct proxy_service *proxy);

#endif