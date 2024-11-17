
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_COMMON_H
#define XFRPC_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <assert.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/event_struct.h>

#include "uthash.h"

// Type definitions
typedef unsigned short ushort;
typedef uint64_t msg_size_t;

// Memory management macros
#define SAFE_FREE(m) do { \
	if (m) { \
		free(m); \
		m = NULL; \
	} \
} while(0)

// Network byte order conversion functions
uint64_t ntoh64(const uint64_t input);
uint64_t hton64(const uint64_t input);

// Message size conversion macros
#define msg_ntoh(l) ntoh64(l)
#define msg_hton(b) hton64(b)

#endif //XFRPC_COMMON_H
