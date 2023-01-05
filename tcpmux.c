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

/** @file tcpmux.c
    @brief xfrp tcp mux implemented
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

#include <unistd.h>
#include <stdlib.h>

#include "common.h"
#include "tcpmux.h"
#include "client.h"
#include "config.h"
#include "debug.h"
#include "control.h"

static uint8_t proto_version = 0;
static uint8_t remote_go_away;
static uint8_t local_go_away;
static uint32_t g_session_id = 1;
static struct tmux_stream *cur_stream = NULL;
static struct tmux_stream *all_stream;

static uint32_t rx_ring_buffer_read(struct bufferevent *bev, struct ring_buffer *ring, uint32_t len);
static uint32_t tx_ring_buffer_write(struct bufferevent *bev, struct ring_buffer *ring, uint32_t len);

void
add_stream(struct tmux_stream *stream)
{
	HASH_ADD_INT(all_stream, id, stream);	
}

void
del_stream(uint32_t id) 
{
	if (!all_stream) return;

	struct tmux_stream *stream = get_stream_by_id(id);
	if (stream)
		HASH_DEL(all_stream, stream);
}

void
clear_stream()
{
	if (!all_stream) return;

	HASH_CLEAR(hh, all_stream);
	all_stream = NULL;
}

struct tmux_stream *
get_stream_by_id(uint32_t id)
{
	if (!all_stream) return NULL;

	struct tmux_stream *stream = NULL;
	HASH_FIND_INT(all_stream, &id, stream);
	return stream;
}

struct tmux_stream *
get_cur_stream() 
{
	return cur_stream;
}

void
set_cur_stream(struct tmux_stream *stream) 
{
	cur_stream = stream;
}

void 
init_tmux_stream(struct tmux_stream *stream, uint32_t id, enum tcp_mux_state state) 
{
	stream->id = id;
	stream->state = state;
	stream->recv_window = MAX_STREAM_WINDOW_SIZE;
	stream->send_window = MAX_STREAM_WINDOW_SIZE;
	
	memset(&stream->tx_ring, 0, sizeof(struct ring_buffer));
	memset(&stream->rx_ring, 0, sizeof(struct ring_buffer));

	add_stream(stream);
};

int
validate_tcp_mux_protocol(struct tcp_mux_header *tmux_hdr)
{
	if (tmux_hdr->version != proto_version) return 0;
	
	if (tmux_hdr->type > GO_AWAY) return 0;

	return 1;
}

void 
tcp_mux_encode(enum tcp_mux_type type, enum tcp_mux_flag flags, uint32_t stream_id, uint32_t length, struct tcp_mux_header *tmux_hdr)
{
	assert(tmux_hdr);
	tmux_hdr->version 	= proto_version;
	tmux_hdr->type		= type;
	tmux_hdr->flags		= htons(flags);
	tmux_hdr->stream_id	= htonl(stream_id);
	tmux_hdr->length	= length?htonl(length):0;
}

static uint32_t
tcp_mux_flag()
{	
	struct common_conf 	*c_conf = get_common_config();
	return c_conf->tcp_mux;
}

void
reset_session_id() {
	g_session_id = 1;
}

uint32_t 
get_next_session_id() {
	uint32_t id = g_session_id;
	g_session_id += 2;
	return id;
}

static void
tcp_mux_send_win_update(struct bufferevent *bout, enum tcp_mux_flag flags, uint32_t stream_id, uint32_t delta)
{
	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(WINDOW_UPDATE, flags, stream_id, delta, &tmux_hdr);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

void
tcp_mux_send_win_update_syn(struct bufferevent *bout, uint32_t stream_id)
{
	if (!tcp_mux_flag()) return;
	
	tcp_mux_send_win_update(bout, SYN, stream_id, 0);
}

void
tcp_mux_send_win_update_ack(struct bufferevent *bout, uint32_t stream_id, uint32_t delta)
{
	if (!tcp_mux_flag()) return;

	tcp_mux_send_win_update(bout, ZERO, stream_id, 0);
}

void
tcp_mux_send_win_update_fin(struct bufferevent *bout, uint32_t stream_id)
{
	if (!tcp_mux_flag()) return;

	tcp_mux_send_win_update(bout, FIN, stream_id, 0);
}

void
tcp_mux_send_win_update_rst(struct bufferevent *bout, uint32_t stream_id)
{
	if (!tcp_mux_flag()) return;

	tcp_mux_send_win_update(bout, RST, stream_id, 0);
}
void
tcp_mux_send_data(struct bufferevent *bout, uint16_t flags, uint32_t stream_id, uint32_t length)
{
	if (!tcp_mux_flag()) return;

	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(DATA, flags, stream_id, length, &tmux_hdr);
	//debug(LOG_DEBUG, "tcp mux [%d] send data len : %d", stream_id, length);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

void 
tcp_mux_send_ping(struct bufferevent *bout, uint32_t ping_id)
{
	if (!tcp_mux_flag()) return;

	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(PING, SYN, 0, ping_id, &tmux_hdr);
	//debug(LOG_DEBUG, "tcp mux send ping syn : %d", ping_id);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

static void 
tcp_mux_handle_ping(struct bufferevent *bout, uint32_t ping_id)
{
	if (!tcp_mux_flag()) return;

	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(PING, ACK, 0, ping_id, &tmux_hdr);
	//debug(LOG_DEBUG, "tcp mux send ping ack : %d", ping_id);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

static void
tcp_mux_send_go_away(struct bufferevent *bout, uint32_t reason)
{
	if (!tcp_mux_flag()) return;

	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(GO_AWAY, 0, 0, reason, &tmux_hdr);
	//debug(LOG_DEBUG, "tcp mux send ping ack : %d", ping_id);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));

}

static int
process_flags(uint16_t flags, struct tmux_stream *stream)
{
	uint32_t close_stream = 0;
	if ( (flags&ACK) == ACK ) {
		if (stream->state == SYN_SEND)
			stream->state = ESTABLISHED;
	} else if ( (flags&FIN) == FIN ) {
		switch(stream->state) {
		case SYN_SEND:
		case SYN_RECEIVED:
		case ESTABLISHED:
			stream->state = REMOTE_CLOSE;
			break;
		case LOCAL_CLOSE:
			stream->state = CLOSED;
			close_stream = 1;
			break;
		default:
			debug(LOG_ERR, "unexpected FIN flag in state %d", stream->state);
			assert(0);
			return 0;
		}
	} else if ( (flags&RST) == RST ) {
		stream->state = RESET;
		close_stream = 1;
	}

	if (close_stream) {
		debug(LOG_DEBUG, "free stream %d", stream->id);		
		del_proxy_client_by_stream_id(stream->id);
	}

	return 1;
}

static uint16_t
get_send_flags(struct tmux_stream *stream)
{
	uint16_t flags = 0;
	
	switch (stream->state) {
	case INIT:
		flags |= SYN;
		stream->state = SYN_SEND;
		break;			
	case SYN_RECEIVED:
		flags |= ACK;
		stream->state = ESTABLISHED;
		break;
	default:
		break;
	} 

	return flags;
}

void
send_window_update(struct bufferevent *bout, struct tmux_stream *stream, uint32_t length)
{
	uint32_t max = MAX_STREAM_WINDOW_SIZE;
	uint32_t delta = (max - length) - stream->recv_window;

	uint16_t flags = get_send_flags(stream);	

	if (delta < max/2 && flags == 0)
		return;

	stream->recv_window += delta;
	tcp_mux_send_win_update(bout, flags, stream->id, delta);
	//debug(LOG_DEBUG, "send window update: flags %d, stream_id %d delta %d, recv_window %u length %u", 
	//				flags, stream->id, delta, stream->recv_window, length);
}

static int
rx_ring_buffer_pop(struct ring_buffer *ring, uint8_t *data, uint32_t len)
{
	assert(ring->sz >= len);
	assert(data != NULL);
	
	uint32_t i = 0;
	while(i < len) {
		data[i] = ring->data[ring->cur++];
		if (ring->cur == RBUF_SIZE)
			ring->cur = 0;
		i++;
		ring->sz--;
	}

	assert(i == len);
	return len;
}

static int
process_data(struct tmux_stream *stream, uint32_t length, uint16_t flags, 
				void (*fn)(uint8_t *, int, void *), void *param)
{
	if (!process_flags(flags, stream)) return 0;


	if (length > stream->recv_window) {
		debug(LOG_ERR, "receive window exceed (remain %d, recv %d)", stream->recv_window, length);
		return 0;
	}
	
	stream->recv_window -= length;

	struct proxy_client *pc = (struct proxy_client *)param;
	if (!pc || (pc && !pc->local_proxy_bev)) {
		uint8_t *data = (uint8_t *)calloc(length, 1);
		rx_ring_buffer_pop(&stream->rx_ring, data, length);
		fn(data, length, pc);
		free(data);
	} else {
		tx_ring_buffer_write(pc->local_proxy_bev, &stream->rx_ring, length);
	}
	
	struct bufferevent *bout = get_main_control()->connect_bev;
	send_window_update(bout, stream, length);	

	return length;
}

static int
incr_send_window(struct bufferevent *bev, struct tcp_mux_header *tmux_hdr, uint16_t flags, struct tmux_stream *stream)
{
    if(!stream){
        return 0;
    }

	if (!process_flags(flags, stream))
		return 0;
	uint32_t length = ntohl(tmux_hdr->length);

	if (stream->send_window == 0) bufferevent_enable(bev, EV_READ);
	stream->send_window += length;
	//debug(LOG_DEBUG, "incr_send_window : stream_id %d length %d send_window %d", 
	//				stream->id, length, stream->send_window);

	return 1;
}

static int
incoming_stream(uint32_t stream_id)
{
	if (local_go_away) {
		struct bufferevent *bout = get_main_control()->connect_bev;
		tcp_mux_send_win_update_rst(bout, stream_id);
		return 0;
	}
	
	// TODO
	// create new stream
	return 1;
}

void
handle_tcp_mux_ping(struct tcp_mux_header *tmux_hdr)
{
	uint16_t flags = ntohs(tmux_hdr->flags);
	uint32_t ping_id = ntohl(tmux_hdr->length);

	if ( (flags&SYN) == SYN) {
		struct bufferevent *bout = get_main_control()->connect_bev;
		tcp_mux_handle_ping(bout, ping_id);
	}
}

void
handle_tcp_mux_go_away(struct tcp_mux_header *tmux_hdr)
{
	uint32_t code = ntohl(tmux_hdr->length);
	switch(code) {
	case NORMAL:
		remote_go_away = 1;
		break;
	case PROTO_ERR:
		debug(LOG_ERR, "receive protocol error go away");	
		break;
	case INTERNAL_ERR:
		debug(LOG_ERR, "receive internal error go away");	
		break;
	default:
		debug(LOG_ERR, "receive unexpected go away");	
	}
}

uint32_t
tmux_stream_read(struct bufferevent *bev, struct tmux_stream *stream, uint32_t len)
{
	assert(stream != NULL);
	if (stream->state != ESTABLISHED) {
		debug(LOG_WARNING, "stream %d state is %d : not ESTABLISHED, discard its data len %d", stream->id, stream->state, len);
	}

	return rx_ring_buffer_read(bev, &stream->rx_ring, len);
}

int
handle_tcp_mux_stream(struct tcp_mux_header *tmux_hdr, handle_data_fn_t fn)
{
	uint32_t stream_id = ntohl(tmux_hdr->stream_id);
	uint16_t flags = ntohs(tmux_hdr->flags);
	
	//debug(LOG_DEBUG, "handle_tcp_mux_stream stream_id %d type %d flags %d", stream_id, tmux_hdr->type, flags);

	if ( (flags&SYN) == SYN) {
		debug(LOG_INFO, "!!!! as xfrpc, it should not be here %d", stream_id);
		if (!incoming_stream(stream_id))
			return 0;
	}

	struct tmux_stream *stream = get_stream_by_id(stream_id);

    if(!stream){
        return 0;
    }

	struct proxy_client *pc = get_proxy_client(stream_id);

	if (tmux_hdr->type == WINDOW_UPDATE) {
		struct bufferevent *bev = pc?pc->local_proxy_bev: get_main_control()->connect_bev;
		if (!incr_send_window(bev, tmux_hdr, flags, stream)) {
			struct bufferevent *bout = get_main_control()->connect_bev;
			tcp_mux_send_go_away(bout, PROTO_ERR);
		}
		return 0;
	}
	
	struct bufferevent *bout = get_main_control()->connect_bev;
	if (stream->state != ESTABLISHED) {
		return 0;
	}

	int32_t length = ntohl(tmux_hdr->length);
	if (!process_data(stream, length, flags, fn, (void *)pc)) {
		tcp_mux_send_go_away(bout, PROTO_ERR);
		return 0;
	}

	return length;
}

static int
tx_ring_buffer_append(struct ring_buffer *ring, uint8_t *data, uint32_t len)
{
	uint32_t left = WBUF_SIZE - ring->sz;	
	assert(left >= len);
	int i = 0;
	for (; i < len; i++) {
		ring->data[ring->end++] = data[i];
		if (ring->end == WBUF_SIZE) ring->end = 0;
		ring->sz++;
		if (ring->cur == ring->end) {
			break;
		}
	}

	return i;
}

static uint32_t
rx_ring_buffer_read(struct bufferevent *bev, struct ring_buffer *ring, uint32_t len)
{
	if (ring->sz == RBUF_SIZE) {
		debug(LOG_ERR, "ring buffer is full");
		return 0;
	}
	
	uint32_t cap = RBUF_SIZE - ring->sz;
	if (len > cap) {
		debug(LOG_INFO, "prepare read data [%d] out size ring capacity [%d]", len, cap);
		len = cap;
	}

	for (int i = 0; i < len; i++) {
		bufferevent_read(bev, &ring->data[ring->end++], 1);
		if (ring->end == RBUF_SIZE) ring->end = 0;
		ring->sz++;
		if (ring->cur == ring->end) {
			break;
		}
	}

	return len;

}

static uint32_t
tx_ring_buffer_write(struct bufferevent *bev, struct ring_buffer *ring, uint32_t len)
{
	if (ring->sz == 0) {
		debug(LOG_ERR, "ring buffer is empty");
		return 0;
	}
	
	if (len > ring->sz) {
		debug(LOG_INFO, "prepare write data [%d] out size ring data [%d]", len, ring->sz);
		len = ring->sz;
	}

	while(len > 0) {
		bufferevent_write(bev, &ring->data[ring->cur++], 1);
		len--;
		ring->sz--;;
		if (ring->cur == WBUF_SIZE) ring->cur = 0;
		if (ring->cur == ring->end) {
			assert(ring->sz == 0);
			break;
		}
	}

	return len;
}

uint32_t 
tmux_stream_write(struct bufferevent *bev, uint8_t *data, uint32_t length, struct tmux_stream *stream)
{
	switch(stream->state) {
	case LOCAL_CLOSE:
	case CLOSED:
	case RESET:
		debug(LOG_INFO, "stream %d state is closed", stream->id);
		return 0;
	default:
		break;
	}
	
	struct ring_buffer *tx_ring = &stream->tx_ring;	
	uint32_t left = WBUF_SIZE - tx_ring->sz;	
	if (stream->send_window == 0) {
		debug(LOG_INFO, "stream %d send_window is zero, length %d left %d", stream->id, length, left);
		tx_ring_buffer_append(tx_ring, data, length);
		return 0;
	}

	uint16_t flags = get_send_flags(stream);
	uint32_t max = length;
	struct bufferevent *bout = get_main_control()->connect_bev;
	//debug(LOG_DEBUG, "tmux_stream_write stream id %u: send_window %u tx_ring sz %u length %u", 
	//				stream->id, stream->send_window, tx_ring->sz, length);
	if (stream->send_window < tx_ring->sz) {
		debug(LOG_INFO, " send_window %u less than tx_ring size %u", stream->send_window, tx_ring->sz);
		max = stream->send_window;
		tcp_mux_send_data(bout, flags, stream->id, max);
		tx_ring_buffer_write(bev, tx_ring, max);
		tx_ring_buffer_append(tx_ring, data, length);
	} else if (stream->send_window < tx_ring->sz + length) {
		debug(LOG_INFO, " send_window %u less than  %u", stream->send_window, tx_ring->sz+length);
		max = stream->send_window;
		tcp_mux_send_data(bout, flags, stream->id, max);
		if (tx_ring->sz > 0)
			tx_ring_buffer_write(bev, tx_ring, tx_ring->sz);
		bufferevent_write(bev, data, max - tx_ring->sz);
		tx_ring_buffer_append(tx_ring, data + max - tx_ring->sz, length + tx_ring->sz - max);
	} else {
		max = tx_ring->sz + length;
		tcp_mux_send_data(bout, flags, stream->id, max);
		if (tx_ring->sz > 0)
			tx_ring_buffer_write(bev, tx_ring, tx_ring->sz);
		bufferevent_write(bev, data, length);
	}
	
	stream->send_window -= max;

	return max;
}

int
tmux_stream_close(struct bufferevent *bout, struct tmux_stream *stream)
{
	uint8_t flag = 0;
	switch(stream->state) {
	case SYN_SEND:
	case SYN_RECEIVED:
	case ESTABLISHED:
		stream->state = LOCAL_CLOSE;
		break;
	case LOCAL_CLOSE:
	case REMOTE_CLOSE:
		flag = 1;
		stream->state = CLOSED;
		break;
	case CLOSED:
	case RESET:
	default:
		return 0;
	}
	
	uint16_t flags = get_send_flags(stream);
	flags |= FIN;
	tcp_mux_send_win_update(bout, flags, stream->id, 0);	
	if (!flag) return 1;

	debug(LOG_DEBUG, "del proxy client %d", stream->id);
	del_proxy_client_by_stream_id(stream->id);
	return 0;
}


