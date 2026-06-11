// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <netinet/tcp.h>
#include <stdatomic.h>

#include "client.h"
#include "common.h"
#include "config.h"
#include "control.h"
#include "debug.h"
#include "proxy.h"
#include "tcpmux.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/**
 * @brief Zero-copy transfer of @p len bytes from @p src to @p dst.
 *
 * Uses evbuffer_remove_buffer to move exactly @p len bytes from src to dst.
 * This avoids application-level payload memcpy on the forwarding path.
 *
 * @return Number of bytes transferred.
 */
size_t evbuffer_zc_transfer(struct evbuffer *src,
                            struct evbuffer *dst,
                            size_t len) {
	if (!src || !dst || len == 0) return 0;

	size_t avail = evbuffer_get_length(src);
	size_t n = MIN(len, avail);
	if (n == 0) return 0;

    ssize_t moved = evbuffer_remove_buffer(src, dst, n);
    if (moved <= 0) {
        return 0;
    }

    return (size_t)moved;
}

/**
 * @brief Protocol and state management variables
 */
static uint8_t proto_version = 0;     /* Protocol version number */
static uint8_t remote_go_away = 0;    /* Flag indicating remote end wants to close */
static uint8_t local_go_away = 0;     /* Flag indicating local end wants to close */

/**
 * @brief Session management variables
 */
static _Atomic uint32_t g_session_id = 1;     /* Global session ID counter (starts at 1) */

/**
 * @brief Stream management variables
 */
static struct tmux_stream *cur_stream = NULL;  /* Currently active stream */
static struct tmux_stream *all_stream = NULL;  /* Hash table of all streams */

/**
 * @brief Adds a stream to the hash table of all streams.
 */
void add_stream(struct tmux_stream *stream) {
    if (!stream) {
        debug(LOG_ERR, "Cannot add NULL stream");
        return;
    }

    struct tmux_stream *existing = NULL;
    HASH_FIND_INT(all_stream, &stream->id, existing);
    if (existing) {
        debug(LOG_WARNING, "Stream %u already exists in hash table", stream->id);
        return;
    }

    HASH_ADD_INT(all_stream, id, stream);
    debug(LOG_DEBUG, "Added stream %u to hash table", stream->id);
}

/**
 * @brief Deletes a stream with the specified ID from the hash table.
 */
void del_stream(uint32_t id) {
    if (!all_stream) {
        debug(LOG_DEBUG, "Stream hash table not initialized");
        return;
    }

    struct tmux_stream *stream = NULL;
    HASH_FIND_INT(all_stream, &id, stream);

    if (stream) {
        HASH_DEL(all_stream, stream);
        debug(LOG_DEBUG, "Stream %u removed from hash table", id);
    } else {
        debug(LOG_DEBUG, "Stream %u not found in hash table", id);
    }
}

/**
 * @brief Clears all streams from the global hash table.
 */
void clear_stream(void) {
    if (all_stream) {
        HASH_CLEAR(hh, all_stream);
        all_stream = NULL;
        debug(LOG_DEBUG, "Cleared all streams from hash table");
    }
}

/**
 * @brief Retrieves a stream from the global hash table by its ID.
 */
struct tmux_stream *get_stream_by_id(uint32_t id) {
    if (!all_stream) {
        debug(LOG_DEBUG, "Stream hash table not initialized");
        return NULL;
    }

    struct tmux_stream *stream = NULL;
    HASH_FIND_INT(all_stream, &id, stream);

    if (!stream) {
        debug(LOG_DEBUG, "Stream %u not found", id);
    }

    return stream;
}

/**
 * @brief Retrieves the current tmux stream.
 */
struct tmux_stream *get_cur_stream() {
    return cur_stream;
}

/**
 * @brief Sets the current tmux stream.
 */
void set_cur_stream(struct tmux_stream *stream) {
    cur_stream = stream;
    debug(LOG_DEBUG, "Current stream %s", stream ? "updated" : "cleared");
}

/**
 * @brief Initializes a tmux stream with the given parameters.
 */
void init_tmux_stream(struct tmux_stream *stream, uint32_t id, enum tcp_mux_state state) {
    if (!stream) {
        debug(LOG_ERR, "Invalid stream pointer");
        return;
    }

    if (state > RESET) {
        debug(LOG_ERR, "Invalid stream state: %d", state);
        return;
    }

    stream->id = id;
    stream->state = state;
    stream->recv_window = MAX_STREAM_WINDOW_SIZE;  // 8MB
    stream->send_window = 256 * 1024;  // 256KB initial (matches yamux initialStreamWindow)

    add_stream(stream);
    debug(LOG_DEBUG, "Initialized stream %u with state %d", id, state);
}

/**
 * @brief Releases per-stream temporary resources.
 */
void tmux_stream_release(struct tmux_stream *stream) {
    // tx_frame_buffer已移除，无需释放
    (void)stream;
}

/**
 * @brief Validates the TCP MUX protocol header.
 */
int validate_tcp_mux_protocol(struct tcp_mux_header *tmux_hdr) {
    if (tmux_hdr->version != proto_version)
        return 0;

    if (tmux_hdr->type > GO_AWAY)
        return 0;

    return 1;
}

/**
 * @brief Encodes a TCP multiplexer header with the specified parameters
 */
void tcp_mux_encode(enum tcp_mux_type type, enum tcp_mux_flag flags,
                    uint32_t stream_id, uint32_t length,
                    struct tcp_mux_header *tmux_hdr) {
    if (!tmux_hdr) {
        debug(LOG_ERR, "NULL header pointer provided");
        return;
    }

    if (type > GO_AWAY) {
        debug(LOG_ERR, "Invalid TCP MUX type: %d", type);
        return;
    }

    tmux_hdr->version = proto_version;
    tmux_hdr->type = type;
    tmux_hdr->flags = htons(flags);
    tmux_hdr->stream_id = htonl(stream_id);
    tmux_hdr->length = length ? htonl(length) : 0;
}

/**
 * @brief Gets the TCP multiplexing configuration flag.
 */
static uint32_t tcp_mux_flag() {
    static int cached = -1;
    if (cached >= 0)
        return cached;
    struct common_conf *c_conf = get_common_config();
    if (!c_conf) {
        debug(LOG_ERR, "Failed to get common configuration");
        return 0;
    }
    cached = c_conf->tcp_mux;
    return cached;
}

/**
 * @brief Resets the global session ID to its initial value.
 */
void reset_session_id() {
    atomic_store(&g_session_id, 1);
}

/**
 * @brief Generates the next unique session ID.
 */
uint32_t get_next_session_id() {
    uint32_t current_id = atomic_fetch_add(&g_session_id, 2);
    return current_id;
}

/**
 * @brief Sends a TCP multiplexer window update message
 */
static void tcp_mux_send_win_update(struct bufferevent *bout,
                                   enum tcp_mux_flag flags,
                                   uint32_t stream_id,
                                   uint32_t delta) {
    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for window update");
        return;
    }

    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(WINDOW_UPDATE, flags, stream_id, delta, &tmux_hdr);

    if (bufferevent_write(bout, &tmux_hdr, sizeof(tmux_hdr)) < 0) {
        debug(LOG_ERR, "Failed to send window update for stream %u", stream_id);
        return;
    }

    debug(LOG_DEBUG, "Sent window update: stream=%u, delta=%u, flags=%u",
          stream_id, delta, flags);
}

/**
 * @brief Sends a window update with SYN flag for a TCP multiplexed stream.
 */
void tcp_mux_send_win_update_syn(struct bufferevent *bout, uint32_t stream_id) {
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for SYN");
        return;
    }

    tcp_mux_send_win_update(bout, SYN, stream_id, 0);
    debug(LOG_DEBUG, "Sent SYN for stream %u", stream_id);
}

/**
 * @brief Sends a window update acknowledgment for a TCP multiplexed stream.
 */
void tcp_mux_send_win_update_ack(struct bufferevent *bout, uint32_t stream_id,
                                uint32_t delta) {
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for ACK");
        return;
    }

    tcp_mux_send_win_update(bout, ACK, stream_id, 0);
    debug(LOG_DEBUG, "Sent ACK for stream %u", stream_id);
}

/**
 * Sends a window update with a FIN flag for a given stream.
 */
void tcp_mux_send_win_update_fin(struct bufferevent *bout, uint32_t stream_id) {
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for FIN");
        return;
    }

    tcp_mux_send_win_update(bout, FIN, stream_id, 0);
    debug(LOG_DEBUG, "Sent FIN for stream %u", stream_id);
}

/**
 * @brief Sends a window update with RST flag for a TCP multiplexed stream
 */
void tcp_mux_send_win_update_rst(struct bufferevent *bout, uint32_t stream_id) {
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for RST");
        return;
    }

    tcp_mux_send_win_update(bout, RST, stream_id, 0);
    debug(LOG_DEBUG, "Sent RST for stream %u", stream_id);
}

/**
 * @brief Sends data over a TCP multiplexed connection.
 */
void tcp_mux_send_data(struct bufferevent *bout, enum tcp_mux_flag flags,
                       uint32_t stream_id, uint32_t length) {
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for sending data");
        return;
    }

    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(DATA, flags, stream_id, length, &tmux_hdr);
    
    if (bufferevent_write(bout, &tmux_hdr, sizeof(tmux_hdr)) < 0) {
        debug(LOG_ERR, "Failed to send data header for stream %u", stream_id);
    }
}

/**
 * @brief Sends a ping message over a TCP multiplexed connection
 */
void tcp_mux_send_ping(struct bufferevent *bout, uint32_t ping_id) {
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for ping");
        return;
    }

    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(PING, SYN, 0, ping_id, &tmux_hdr);
    
    if (bufferevent_write(bout, &tmux_hdr, sizeof(tmux_hdr)) < 0) {
        debug(LOG_ERR, "Failed to send ping message");
    }
}

/**
 * @brief Handles TCP multiplexer ping messages by sending an acknowledgment.
 */
static void tcp_mux_handle_ping(struct bufferevent *bout, uint32_t ping_id) {
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for ping response");
        return;
    }

    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(PING, ACK, 0, ping_id, &tmux_hdr);
    
    if (bufferevent_write(bout, &tmux_hdr, sizeof(tmux_hdr)) < 0) {
        debug(LOG_ERR, "Failed to send ping acknowledgment");
    }
}

/**
 * @brief Sends a GO_AWAY message using the provided bufferevent.
 */
static void tcp_mux_send_go_away(struct bufferevent *bout, uint32_t reason) {
    if (!tcp_mux_flag() || !bout) {
        debug(LOG_ERR, "Cannot send GO_AWAY: invalid state or parameters");
        return;
    }

    if (reason > INTERNAL_ERR) {
        debug(LOG_WARNING, "Invalid GO_AWAY reason code: %u", reason);
        reason = INTERNAL_ERR;
    }

    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(GO_AWAY, 0, 0, reason, &tmux_hdr);
    
    if (bufferevent_write(bout, &tmux_hdr, sizeof(tmux_hdr)) < 0) {
        debug(LOG_ERR, "Failed to send GO_AWAY message");
    }
}

/**
 * @brief Processes the given flags and updates the state of the tmux stream accordingly.
 */
static int process_flags(uint16_t flags, struct tmux_stream *stream) {
    bool should_close = false;

    if (flags & ACK) {
        if (stream->state == SYN_SEND) {
            stream->state = ESTABLISHED;
        }
    }

    if (flags & FIN) {
        switch (stream->state) {
            case SYN_SEND:
            case SYN_RECEIVED:
            case ESTABLISHED:
                stream->state = REMOTE_CLOSE;
                break;
            case LOCAL_CLOSE:
                stream->state = CLOSED;
                should_close = true;
                break;
            case INIT:
                debug(LOG_WARNING, "FIN received in INIT state for stream %d, treating as reset", stream->id);
                stream->state = RESET;
                should_close = true;
                break;
            case CLOSED:
            case RESET:
                debug(LOG_DEBUG, "FIN received in terminal state %d for stream %d, ignoring", stream->state, stream->id);
                return 1;
            default:
                debug(LOG_ERR, "unexpected FIN flag in state %d for stream %d", stream->state, stream->id);
                return 0;
        }
    }

    if (flags & RST) {
        stream->state = RESET;
        should_close = true;
    }

    if (should_close) {
        debug(LOG_DEBUG, "free stream %d", stream->id);
        del_proxy_client_by_stream_id(stream->id);
    }

    return 1;
}

/**
 * @brief Get the flags to be sent based on the current state of the stream.
 */
static enum tcp_mux_flag get_send_flags(struct tmux_stream *stream) {
    enum tcp_mux_flag flags = ZERO;

    if (!stream) {
        return flags;
    }

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

/**
 * @brief Sends a window update message for stream flow control.
 */
void send_window_update(struct bufferevent *bout, struct tmux_stream *stream, uint32_t length) {
    if (length == 0) {
        enum tcp_mux_flag flags = get_send_flags(stream);
        if (flags != ZERO) {
            tcp_mux_send_win_update(bout, flags, stream->id, 0);
        }
        return;
    }

    const uint32_t max_window = MAX_STREAM_WINDOW_SIZE;
    uint32_t delta = (stream->recv_window < max_window) ? (max_window - stream->recv_window) : 0;
    if (delta == 0) {
        return;
    }

    enum tcp_mux_flag flags = get_send_flags(stream);
    uint32_t old_recv_window = stream->recv_window;
    stream->recv_window = max_window;
    debug(LOG_DEBUG, "WUP send stream=%u delta=%u rw %u->%u",
          stream->id, delta, old_recv_window, stream->recv_window);
    tcp_mux_send_win_update(bout, flags, stream->id, delta);
}

/**
 * @brief Processes data from a tmux DATA frame and dispatches to protocol handlers.
 *
 * Reads the payload directly from the control bev (no intermediate ring buffer)
 * and dispatches to the appropriate protocol handler.
 */
int process_data(struct bufferevent *bev, struct tmux_stream *stream,
                 uint32_t length, uint16_t flags,
                 void (*handle_fn)(uint8_t *, int, void *), void *param) {
    if (!stream || !handle_fn) {
        debug(LOG_ERR, "Invalid parameters in process_data");
        return 0;
    }

    uint32_t stream_id = stream->id;

    if (!process_flags(flags, stream)) {
        debug(LOG_ERR, "Failed to process flags for stream %d", stream_id);
        return 0;
    }

    if (!get_stream_by_id(stream_id)) {
        debug(LOG_DEBUG, "Stream %d no longer exists", stream_id);
        return length;
    }

    if (length > stream->recv_window) {
        debug(LOG_ERR, "Receive window exceeded (available: %u, requested: %u)",
              stream->recv_window, length);
        return 0;
    }

    stream->recv_window -= length;

    struct proxy_client *pc = (struct proxy_client *)param;
    uint32_t bytes_processed = 0;

    if (!pc || (!pc->local_proxy_bev && !is_socks5_proxy(pc->ps) && !has_service_type(pc->ps))) {
        /* Default callback path: read payload from bev and pass to handler */
        uint8_t *data = calloc(length + 1, sizeof(uint8_t));
        if (!data) {
            debug(LOG_ERR, "Memory allocation failed for data buffer");
            return 0;
        }

        size_t nr = bufferevent_read(bev, data, length);
        if (nr != length) {
            debug(LOG_ERR, "Stream %u: short read %zu/%u in default path",
                  stream_id, nr, length);
            free(data);
            return 0;
        }

        debug(LOG_DEBUG, "Stream %u: entering default callback path length=%u",
              stream_id, length);
        handle_fn(data, length, pc);
        debug(LOG_DEBUG, "Stream %u: leaving default callback path processed=%u",
              stream_id, length);
        free(data);
        bytes_processed = length;
    } else if (has_service_type(pc->ps)) {
        debug(LOG_DEBUG, "Stream %u: entering xdpi path length=%u service_type=%d",
              stream_id, length, pc->ps ? pc->ps->service_type : -1);
        handle_xdpi(pc, bev, length);
        bytes_processed = length;
        debug(LOG_DEBUG, "Stream %u: leaving xdpi path processed=%u",
              stream_id, length);
    } else if (is_socks5_proxy(pc->ps)) {
        debug(LOG_DEBUG, "Stream %u: entering socks5 path length=%u",
              stream_id, length);
        handle_socks5(pc, bev, length);
        bytes_processed = length;
        debug(LOG_DEBUG, "Stream %u: leaving socks5 path processed=%u",
              stream_id, length);
    } else {
        /* Ordinary local forwarding: zero-copy from control bev to local proxy bev */
        debug(LOG_DEBUG, "Stream %u: entering local proxy path length=%u local_proxy_bev=%p",
              stream_id, length, pc->local_proxy_bev);

        struct evbuffer *src = bufferevent_get_input(bev);
        struct evbuffer *dst = bufferevent_get_output(pc->local_proxy_bev);
        bytes_processed = evbuffer_zc_transfer(src, dst, length);

        debug(LOG_DEBUG, "Stream %u: leaving local proxy path processed=%u/%u",
              stream_id, bytes_processed, length);
    }

    struct bufferevent *bout = get_main_control()->connect_bev;
    if (bytes_processed != length) {
        debug(LOG_ERR,
              "Stream %u: incomplete transfer processed=%u expected=%u "
              "pc=%p connected=%d work_started=%d pending_close=%d "
              "xdpi_state=%d socks5_state=%d stream_state=%d "
              "local_proxy_bev=%p recv_window=%u "
              "proxy_type=%s service_type=%d",
              stream_id, bytes_processed, length,
              pc,
              pc ? pc->connected : -1,
              pc ? pc->work_started : -1,
              pc ? pc->pending_close : -1,
              pc ? pc->xdpi_state : -1,
              pc ? pc->state : -1,
              stream->state,
              pc ? pc->local_proxy_bev : NULL,
              stream->recv_window,
              (pc && pc->ps && pc->ps->proxy_type) ? pc->ps->proxy_type : "null",
              (pc && pc->ps) ? pc->ps->service_type : -1);
        tcp_mux_send_win_update_rst(bout, stream->id);
        stream->state = LOCAL_CLOSE;
    } else {
        send_window_update(bout, stream, bytes_processed);
    }

    return length;
}

/**
 * @brief Increases the send window of a multiplexed TCP stream.
 */
static int incr_send_window(struct bufferevent *bev,
                            struct tcp_mux_header *tmux_hdr, uint16_t flags,
                            struct tmux_stream *stream) {
    if (!bev || !tmux_hdr || !stream) {
        debug(LOG_ERR, "Invalid parameters in incr_send_window");
        return 0;
    }

    uint32_t stream_id = stream->id;

    if (!process_flags(flags, stream)) {
        debug(LOG_ERR, "Failed to process flags for stream %d", stream_id);
        return 0;
    }

    if (!get_stream_by_id(stream_id)) {
        debug(LOG_DEBUG, "Stream %d no longer exists", stream_id);
        return 1;
    }

    uint32_t increment = ntohl(tmux_hdr->length);

    if (increment > MAX_STREAM_WINDOW_SIZE) {
        debug(LOG_ERR, "Stream %d: WINDOW_UPDATE increment %u exceeds maximum %u",
              stream_id, increment, MAX_STREAM_WINDOW_SIZE);
        return 0;
    }

    uint32_t old_window = stream->send_window;
    if (stream->send_window > MAX_STREAM_WINDOW_SIZE - increment) {
        debug(LOG_WARNING, "Stream %d: send_window would overflow, capping at %u",
              stream_id, MAX_STREAM_WINDOW_SIZE);
        stream->send_window = MAX_STREAM_WINDOW_SIZE;
    } else {
        stream->send_window += increment;
    }

    if (stream->send_window > MAX_YAMUX_WINDOW_SIZE) {
        debug(LOG_DEBUG, "Stream %u: capping send_window %u to MAX_YAMUX_WINDOW_SIZE %u",
              stream_id, stream->send_window, MAX_YAMUX_WINDOW_SIZE);
        stream->send_window = MAX_YAMUX_WINDOW_SIZE;
    }

    debug(LOG_DEBUG, "WUP recv stream=%u inc=%u sw %u->%u",
          stream_id, increment, old_window, stream->send_window);

    if (stream->send_window == 0) {
        return 1;
    }

    struct proxy_client *pc = get_proxy_client(stream_id);
    if (!pc) {
        return 1;
    }

    if (pc->pending_close) {
        struct bufferevent *bout = get_main_control()->connect_bev;
        if (bout) {
            debug(LOG_INFO, "Stream %d: pending_close, sending FIN", stream_id);
            tmux_stream_close(bout, stream);
        }
        return 1;
    }

    if (old_window == 0 && stream->send_window > 0 && pc->local_proxy_bev) {
        debug(LOG_DEBUG,
              "Stream %u: re-enabling EV_READ after WINDOW_UPDATE local_proxy_bev=%p",
              stream_id, pc->local_proxy_bev);
        bufferevent_enable(pc->local_proxy_bev, EV_READ);
    }

    return 1;
}

/**
 * @brief Handles incoming stream requests
 */
static int incoming_stream(uint32_t stream_id) {
    if (local_go_away) {
        struct bufferevent *bout = get_main_control()->connect_bev;
        tcp_mux_send_win_update_rst(bout, stream_id);
        return 0;
    }

    return 1;
}

/**
 * @brief Handles TCP multiplexer ping messages
 */
void handle_tcp_mux_ping(struct tcp_mux_header *tmux_hdr) {
    if (!tmux_hdr) {
        debug(LOG_ERR, "Invalid TCP MUX header");
        return;
    }

    struct bufferevent *bout = NULL;
    uint16_t flags = ntohs(tmux_hdr->flags);
    uint32_t ping_id = ntohl(tmux_hdr->length);

    if ((flags & SYN) == SYN) {
        if (!(bout = get_main_control()->connect_bev)) {
            debug(LOG_ERR, "No valid bufferevent for ping response");
            return;
        }
        tcp_mux_handle_ping(bout, ping_id);
    }
}

/**
 * @brief Handles TCP multiplexer "go away" messages.
 */
void handle_tcp_mux_go_away(struct tcp_mux_header *tmux_hdr) {
    if (!tmux_hdr) {
        debug(LOG_ERR, "Invalid TCP MUX header");
        return;
    }

    uint32_t code = ntohl(tmux_hdr->length);
    const char *error_msg = NULL;

    switch (code) {
        case NORMAL:
            remote_go_away = 1;
            error_msg = "Normal shutdown requested";
            break;
        case PROTO_ERR:
            error_msg = "Protocol error detected";
            break;
        case INTERNAL_ERR:
            error_msg = "Internal error occurred";
            break;
        default:
            error_msg = "Unexpected error code";
    }

    if (code != NORMAL) {
        debug(LOG_ERR, "GO_AWAY received: %s (code=%u)", error_msg, code);
    } else {
        debug(LOG_INFO, "GO_AWAY received: %s", error_msg);
    }
}

/**
 * @brief Handles TCP multiplexing stream data and control messages (window updates only).
 *
 * With the rx_ring removed, DATA frames are handled directly in handle_tcp_mux
 * by reading the payload from bev and calling process_data. This function now
 * only handles WINDOW_UPDATE messages and flag processing.
 */
int handle_tcp_mux_stream(struct tcp_mux_header *tmux_hdr,
                          handle_data_fn_t fn) {
    if (!tmux_hdr || !fn) {
        return 0;
    }

    uint32_t stream_id = ntohl(tmux_hdr->stream_id);
    uint16_t flags = ntohs(tmux_hdr->flags);

    if ((flags & SYN) == SYN) {
        debug(LOG_INFO, "Unexpected SYN flag received for stream %d in xfrpc", stream_id);
        if (!incoming_stream(stream_id)) {
            debug(LOG_ERR, "Failed to handle incoming SYN for stream %d", stream_id);
        }
        return 0;
    }

    struct tmux_stream *stream = get_stream_by_id(stream_id);
    if (!stream) {
        debug(LOG_ERR, "Stream %d not found", stream_id);
        return 0;
    }

    struct bufferevent *bout = get_main_control()->connect_bev;

    if (tmux_hdr->type == WINDOW_UPDATE) {
        if (!incr_send_window(bout, tmux_hdr, flags, stream)) {
            debug(LOG_ERR, "Protocol error while handling window update");
            tcp_mux_send_go_away(bout, PROTO_ERR);
        }
        return 0;
    }

    return 0;
}

/**
 * @brief Writes data from an evbuffer to a TCP multiplexing stream with flow control.
 */
int tmux_stream_write(struct bufferevent *bev,
                                    struct evbuffer *src,
                                    struct tmux_stream *stream) {
    if (!src || !stream) {
        return -2;
    }

    if (stream->state == LOCAL_CLOSE || stream->state == CLOSED || stream->state == RESET) {
        debug(LOG_INFO, "stream %d state is closed", stream->id);
        return -1;
    }

    size_t available = evbuffer_get_length(src);
    if (available == 0) {
        return 0;
    }

    if (stream->send_window == 0) {
        debug(LOG_DEBUG, "Stream %u: tmux_stream_write blocked, send_window=0", stream->id);
        return 0;
    }

    enum tcp_mux_flag flags = get_send_flags(stream);
    struct bufferevent *bout = bev ? bev : get_main_control()->connect_bev;
    if (!bout) {
        debug(LOG_ERR, "Stream %u: invalid output bufferevent", stream->id);
        return -2;
    }

    struct evbuffer *out = bufferevent_get_output(bout);
    if (!out) {
        debug(LOG_ERR, "Stream %u: invalid output evbuffer", stream->id);
        return -2;
    }

    uint32_t to_send = (uint32_t)available;
    if (to_send > stream->send_window) to_send = stream->send_window;
    if (to_send > DEFAULT_MAX_FRAME_SIZE) to_send = DEFAULT_MAX_FRAME_SIZE;

    if (to_send == 0) {
        return 0;
    }

    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(DATA, flags, stream->id, to_send, &tmux_hdr);

    // 1. 直接写header到out
    if (evbuffer_add(out, &tmux_hdr, sizeof(tmux_hdr)) < 0) {
        debug(LOG_ERR, "Stream %u: failed to append tmux header", stream->id);
        return -2;
    }

    // 2. 直接remove_buffer到out
    ssize_t moved = evbuffer_remove_buffer(src, out, to_send);
    if (moved != (ssize_t)to_send) {
        debug(LOG_ERR, "Stream %u: payload transfer short %zd/%u", stream->id, moved, to_send);
        return -2;
    }

    stream->send_window -= to_send;

    debug(LOG_DEBUG, "Stream %u: tmux_stream_write sent=%u sw=%u",
          stream->id, to_send, stream->send_window);
    return (int)to_send;
}

/**
 * Handles the closure of a TCP multiplexing stream.
 */
int tmux_stream_close(struct bufferevent *bout, struct tmux_stream *stream) {
    uint8_t should_close = 0;

    switch (stream->state) {
        case SYN_SEND:
        case SYN_RECEIVED:
        case ESTABLISHED:
            stream->state = LOCAL_CLOSE;
            break;
        case LOCAL_CLOSE:
        case REMOTE_CLOSE:
            should_close = 1;
            stream->state = CLOSED;
            break;
        case CLOSED:
        case RESET:
        default:
            return 0;
    }

    enum tcp_mux_flag flags = get_send_flags(stream) | FIN;
    tcp_mux_send_win_update(bout, flags, stream->id, 0);

    if (!should_close) {
        return 1;
    }

    debug(LOG_INFO, "del proxy client %d", stream->id);
    del_proxy_client_by_stream_id(stream->id);
    return 0;
}
