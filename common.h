/*
 * Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
