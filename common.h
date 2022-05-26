/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/** @file common.h
    @brief xfrp common header
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/event_struct.h>

#include <assert.h>

#include "uthash.h"

#define BIGENDIAN_64BIT 1
//#define BIGENDIAN_32BIT 1

#define SAFE_FREE(m) 	\
if (m) free(m)

uint64_t ntoh64(const uint64_t input);
uint64_t hton64(const uint64_t input);

#ifdef BIGENDIAN_64BIT
	typedef uint64_t msg_size_t;
	#define msg_ntoh(l)		\
	ntoh64(l)

	#define msg_hton(b) 	\
	hton64(b)

#elif BIGENDIAN_32BIT
	#define msg_ntoh(l)		\
	ntohl(l)

	#define msg_hton(b)		\
	htonl(b)

	typedef uint32_t msg_size_t;
#endif //BIGENDIAN_64BIT

typedef unsigned short ushort;

#endif //_COMMON_H_
