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

/** @file tcpmux.h
    @brief xfrp tcp mux header file
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

#ifndef	__TCP_MUX__
#define	__TCP_MUX__

#include "uthash.h"

enum tcp_mux_type {
	DATA,
	WINDOW_UPDATE,
	PING,
	GO_AWAY,
};

struct tcp_mux_type_desc {
	enum tcp_mux_type type;
	char	*desc;
};

enum tcp_mux_flag {
	ZERO,
	SYN,
	ACK = 1<<1,
	FIN = 1<<2,
	RST = 1<<3,
};

struct __attribute__((__packed__)) tcp_mux_header {
	uint8_t		version;
	uint8_t		type;
	uint16_t	flags;
	uint32_t	stream_id;
	uint32_t	length;
};

struct tcp_mux_flag_desc {
	enum tcp_mux_flag flag;
	char	*desc;
};

enum tcp_mux_state {
	INIT = 0,
	SYN_SEND,
	SYN_RECEIVED,
	ESTABLISHED,
	LOCAL_CLOSE,
	REMOTE_CLOSE,
	CLOSED,
	RESET
};

void tcp_mux_send_win_update_syn(struct bufferevent *bout, uint32_t stream_id);

void tcp_mux_send_win_update_ack(struct bufferevent *bout, uint32_t stream_id, uint32_t delta);

void tcp_mux_send_win_update_fin(struct bufferevent *bout, uint32_t stream_id);

void tcp_mux_send_data(struct bufferevent *bout, uint32_t stream_id, uint32_t length);

void tcp_mux_send_ping(struct bufferevent *bout, uint32_t ping_id);

uint32_t get_next_session_id();

void tcp_mux_encode(enum tcp_mux_type type, enum tcp_mux_flag flags, uint32_t stream_id, uint32_t length, struct tcp_mux_header *tmux_hdr);

void handle_tcp_mux_frps_msg(uint8_t *data, int len, void (*fn)(uint8_t *, int, void *));

#endif
