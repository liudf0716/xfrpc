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

#define	MAX_STREAM_WINDOW_SIZE	256*1024
#define	RBUF_SIZE	32*1024
#define	WBUF_SIZE	32*1024


struct ring_buffer {
	uint32_t cur;
	uint32_t end;
	uint32_t sz;
	uint8_t data[RBUF_SIZE];
};

enum go_away_type {
	NORMAL,
	PROTO_ERR,
	INTERNAL_ERR,
};

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

struct tmux_stream {
	uint32_t	id;
	uint32_t	recv_window;
	uint32_t	send_window;	
	enum tcp_mux_state state;	
	struct ring_buffer	tx_ring;
	struct ring_buffer 	rx_ring;

	// private arguments
	UT_hash_handle hh;
};

typedef void (*handle_data_fn_t)(uint8_t *, int, void *);

void init_tmux_stream(struct tmux_stream *stream, uint32_t id, enum tcp_mux_state state);

int validate_tcp_mux_protocol(struct tcp_mux_header *tmux_hdr);

void send_window_update(struct bufferevent *bout, struct tmux_stream *stream, uint32_t length);

void tcp_mux_send_win_update_syn(struct bufferevent *bout, uint32_t stream_id);

void tcp_mux_send_win_update_ack(struct bufferevent *bout, uint32_t stream_id, uint32_t delta);

void tcp_mux_send_win_update_fin(struct bufferevent *bout, uint32_t stream_id);

void tcp_mux_send_win_update_rst(struct bufferevent *bout, uint32_t stream_id);

void tcp_mux_send_data(struct bufferevent *bout, uint16_t flags, uint32_t stream_id, uint32_t length);

void tcp_mux_send_ping(struct bufferevent *bout, uint32_t ping_id);

uint32_t get_next_session_id();

void tcp_mux_encode(enum tcp_mux_type type, enum tcp_mux_flag flags, 
				uint32_t stream_id, uint32_t length, struct tcp_mux_header *tmux_hdr);

int handle_tcp_mux_stream(struct tcp_mux_header *tmux_hdr, handle_data_fn_t fn);

void handle_tcp_mux_ping(struct tcp_mux_header *tmux_hdr);

void handle_tcp_mux_go_away(struct tcp_mux_header *tmux_hdr);

uint32_t tmux_stream_write(struct bufferevent *bev, uint8_t *data, uint32_t length, struct tmux_stream *stream);

uint32_t tmux_stream_read(struct bufferevent *bev, struct tmux_stream *stream, uint32_t len);

void reset_session_id();

struct tmux_stream *get_cur_stream();

void set_cur_stream(struct tmux_stream *stream);

void add_stream(struct tmux_stream *stream);

void del_stream(uint32_t stream_id);

void clear_stream();

struct tmux_stream* get_stream_by_id(uint32_t id);

int tmux_stream_close(struct bufferevent *bout, struct tmux_stream *stream);

#endif
