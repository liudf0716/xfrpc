/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 3 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, see <http://www.gnu.org/licenses/>. *
\********************************************************************/

/**
 * @file tcpmux.c
 * @brief TCP multiplexer implementation
 * @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
 * @date 2024
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

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

static uint8_t proto_version = 0;
static uint8_t remote_go_away;
static uint8_t local_go_away;
static uint32_t g_session_id = 1;
static struct tmux_stream *cur_stream = NULL;
static struct tmux_stream *all_stream;

/**
 * @brief Adds a stream to the hash table of all streams.
 *
 * This function adds the given stream to the global hash table `all_stream`
 * using the stream's `id` as the key.
 *
 * @param stream A pointer to the `tmux_stream` structure to be added.
 */
void add_stream(struct tmux_stream *stream) {
    HASH_ADD_INT(all_stream, id, stream);
}

/**
 * @brief Deletes a stream with the specified ID from the hash table.
 *
 * This function removes a stream identified by the given ID from the global
 * hash table `all_stream`. If the stream is found, it is deleted from the
 * hash table. Note that the stream itself is not freed in this function; it
 * will be freed when the associated proxy client is freed.
 *
 * @param id The ID of the stream to be deleted.
 */
void del_stream(uint32_t id) {
    if (!all_stream)
        return;

    struct tmux_stream *stream = get_stream_by_id(id);
    if (stream)
        HASH_DEL(all_stream, stream); // no need to free stream, it will be freed
                                      // when proxy client is freed
}

/**
 * @brief Clears the hash table of all streams and sets the pointer to NULL.
 *
 * This function checks if the global variable `all_stream` is not NULL. If it is not NULL,
 * it clears the hash table using `HASH_CLEAR` and then sets `all_stream` to NULL.
 */
void clear_stream() {
    if (!all_stream)
        return;

    HASH_CLEAR(hh, all_stream);
    all_stream = NULL;
}

/**
 * @brief Retrieves a tmux_stream structure by its ID.
 *
 * This function searches for a tmux_stream structure in the global hash table
 * `all_stream` using the provided ID. If the stream is found, it is returned;
 * otherwise, NULL is returned.
 *
 * @param id The ID of the tmux_stream to retrieve.
 * @return A pointer to the tmux_stream structure if found, otherwise NULL.
 */
struct tmux_stream *get_stream_by_id(uint32_t id) {
    if (!all_stream)
        return NULL;

    struct tmux_stream *stream = NULL;
    HASH_FIND_INT(all_stream, &id, stream);
    return stream;
}

/**
 * @brief Retrieves the current tmux stream.
 *
 * This function returns a pointer to the current tmux stream.
 *
 * @return A pointer to the current tmux stream.
 */
struct tmux_stream *get_cur_stream() {
    return cur_stream;
}

/**
 * @brief Sets the current tmux stream.
 *
 * This function assigns the provided tmux stream to the global variable `cur_stream`.
 *
 * @param stream Pointer to the tmux stream to be set as the current stream.
 */
void set_cur_stream(struct tmux_stream *stream) { 
    cur_stream = stream; 
}

/**
 * @brief Initializes a tmux stream with the given parameters.
 *
 * This function sets up a tmux stream by initializing its ID, state,
 * receive window, send window, and ring buffers. It also adds the stream
 * to the stream management system.
 *
 * @param stream Pointer to the tmux_stream structure to be initialized.
 * @param id The unique identifier for the stream.
 * @param state The initial state of the stream, specified by the tcp_mux_state enum.
 */
void init_tmux_stream(struct tmux_stream *stream, uint32_t id,
                      enum tcp_mux_state state) {
    stream->id = id;
    stream->state = state;
    stream->recv_window = MAX_STREAM_WINDOW_SIZE;
    stream->send_window = MAX_STREAM_WINDOW_SIZE;

    memset(&stream->tx_ring, 0, sizeof(struct ring_buffer));
    memset(&stream->rx_ring, 0, sizeof(struct ring_buffer));

    add_stream(stream);
};

/**
 * @brief Validates the TCP MUX protocol header.
 *
 * This function checks if the provided TCP MUX header has a valid version
 * and type. The header is considered valid if its version matches the
 * expected protocol version and its type does not exceed the maximum
 * allowed type (GO_AWAY).
 *
 * @param tmux_hdr Pointer to the TCP MUX header to be validated.
 * @return Returns 1 if the header is valid, 0 otherwise.
 */
int validate_tcp_mux_protocol(struct tcp_mux_header *tmux_hdr) {
    if (tmux_hdr->version != proto_version)
        return 0;

    if (tmux_hdr->type > GO_AWAY)
        return 0;

    return 1;
}

/**
 * Encodes the TCP MUX header with the given parameters.
 *
 * @param type The type of the TCP MUX message.
 * @param flags The flags associated with the TCP MUX message.
 * @param stream_id The stream ID for the TCP MUX message.
 * @param length The length of the TCP MUX message payload.
 * @param tmux_hdr Pointer to the tcp_mux_header structure to be filled.
 */
void tcp_mux_encode(enum tcp_mux_type type, enum tcp_mux_flag flags,
                    uint32_t stream_id, uint32_t length,
                    struct tcp_mux_header *tmux_hdr) {
    assert(tmux_hdr);
    tmux_hdr->version = proto_version;
    tmux_hdr->type = type;
    tmux_hdr->flags = htons(flags);
    tmux_hdr->stream_id = htonl(stream_id);
    tmux_hdr->length = length ? htonl(length) : 0;
}

/**
 * @brief Retrieves the TCP multiplexing flag from the common configuration.
 *
 * This function accesses the common configuration structure and returns the
 * value of the TCP multiplexing flag.
 *
 * @return The TCP multiplexing flag as a 32-bit unsigned integer.
 */
static uint32_t tcp_mux_flag() {
    struct common_conf *c_conf = get_common_config();
    return c_conf->tcp_mux;
}

/**
 * @brief Resets the global session ID to its initial value.
 *
 * This function sets the global session ID (g_session_id) to 1.
 * It is typically used to reinitialize the session ID counter.
 */
void reset_session_id() { g_session_id = 1; }

/**
 * @brief Generates the next session ID.
 *
 * This function retrieves the current global session ID, increments it by 2,
 * and returns the original value. The global session ID is updated to ensure
 * that each call to this function returns a unique session ID.
 *
 * @return The next session ID.
 */
uint32_t get_next_session_id() {
    uint32_t id = g_session_id;
    g_session_id += 2;
    return id;
}

/**
 * @brief Sends a TCP mux window update.
 *
 * This function constructs a TCP mux header for a window update and writes it
 * to the specified bufferevent output buffer.
 *
 * @param bout The bufferevent output buffer to write the window update to.
 * @param flags The TCP mux flags to include in the header.
 * @param stream_id The stream ID for which the window update is being sent.
 * @param delta The window size increment.
 */
static void tcp_mux_send_win_update(struct bufferevent *bout,
                                    enum tcp_mux_flag flags, uint32_t stream_id,
                                    uint32_t delta) {
    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(WINDOW_UPDATE, flags, stream_id, delta, &tmux_hdr);
    bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

/**
 * Sends a window update with SYN flag for a given stream.
 *
 * This function checks if the TCP multiplexing flag is enabled. If it is,
 * it sends a window update with the SYN flag for the specified stream ID.
 *
 * @param bout The bufferevent to send the window update on.
 * @param stream_id The ID of the stream to send the window update for.
 */
/**
 * @brief Sends a window update with SYN flag for a TCP multiplexed stream.
 *
 * This function sends a window update message with the SYN flag set for 
 * a specified stream. The message is only sent if TCP multiplexing is enabled.
 *
 * @param bout The bufferevent to write the window update to
 * @param stream_id The ID of the stream to send the update for
 *
 * @note Function silently returns if TCP multiplexing is disabled
 *       or if bufferevent is invalid
 */
void tcp_mux_send_win_update_syn(struct bufferevent *bout, uint32_t stream_id) {
    // Early return if TCP multiplexing is disabled
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    // Validate bufferevent
    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for SYN");
        return;
    }

    // Send window update with SYN flag
    tcp_mux_send_win_update(bout, SYN, stream_id, 0);
    debug(LOG_DEBUG, "Sent SYN for stream %u", stream_id);
}

/**
 * @brief Sends a window update acknowledgment for a TCP multiplexed stream.
 *
 * This function sends a window update acknowledgment for a specified stream
 * if the TCP multiplexing flag is enabled. It calls the `tcp_mux_send_win_update`
 * function with the provided stream ID and a delta value of 0.
 *
 * @param bout Pointer to the bufferevent structure.
 * @param stream_id The ID of the stream for which the window update acknowledgment is sent.
 * @param delta The delta value for the window update (currently unused, set to 0).
 */
/**
 * @brief Sends a window update acknowledgment for a TCP multiplexed stream.
 *
 * This function sends a window update acknowledgment message for a specified stream
 * if TCP multiplexing is enabled. It includes validation checks and proper error handling.
 *
 * @param bout Pointer to the bufferevent structure to send the acknowledgment through
 * @param stream_id The ID of the stream being acknowledged
 * @param delta The window size delta (currently unused, kept for API compatibility)
 *
 * @note Function silently returns if TCP multiplexing is disabled or if bufferevent is invalid
 */
void tcp_mux_send_win_update_ack(struct bufferevent *bout, uint32_t stream_id,
                                uint32_t delta) {
    // Early return if TCP multiplexing is disabled
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    // Validate bufferevent
    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for ACK");
        return;
    }

    // Send window update with ACK flag
    tcp_mux_send_win_update(bout, ACK, stream_id, 0);
    debug(LOG_DEBUG, "Sent ACK for stream %u", stream_id);
}

/**
 * Sends a window update with a FIN flag for a given stream.
 *
 * This function checks if the TCP multiplexing flag is enabled. If it is,
 * it sends a window update with the FIN flag for the specified stream ID.
 *
 * @param bout A pointer to the bufferevent structure where the window update will be sent.
 * @param stream_id The ID of the stream for which the window update with FIN flag is sent.
 */
void tcp_mux_send_win_update_fin(struct bufferevent *bout, uint32_t stream_id) {
    // Early return if TCP multiplexing is disabled
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    // Validate bufferevent
    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for FIN");
        return;
    }

    // Send window update with FIN flag
    tcp_mux_send_win_update(bout, FIN, stream_id, 0);
    debug(LOG_DEBUG, "Sent FIN for stream %u", stream_id);
}

/**
 * @brief Sends a window update with a reset flag for a TCP multiplexed stream.
 *
 * This function checks if the TCP multiplexing flag is enabled. If it is,
 * it sends a window update with the reset (RST) flag for the specified stream ID.
 *
 * @param bout Pointer to the bufferevent structure used for sending the update.
 * @param stream_id The ID of the stream for which the window update is being sent.
 */
/**
 * @brief Sends a window update with RST flag for a TCP multiplexed stream
 *
 * This function sends a window update message with the RST (reset) flag set for
 * the specified stream ID. The message is only sent if TCP multiplexing is enabled.
 *
 * @param bout The bufferevent to write the window update to
 * @param stream_id The ID of the stream to reset
 *
 * @note Function silently returns if TCP multiplexing is disabled
 *       or if bufferevent is invalid
 */
void tcp_mux_send_win_update_rst(struct bufferevent *bout, uint32_t stream_id) {
    // Early return if TCP multiplexing is disabled
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    // Validate bufferevent
    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for RST");
        return;
    }

    // Send window update with RST flag
    tcp_mux_send_win_update(bout, RST, stream_id, 0);
    debug(LOG_DEBUG, "Sent RST for stream %u", stream_id);
}

/**
 * @brief Sends data over a TCP multiplexed connection.
 *
 * This function sends data over a TCP multiplexed connection using the provided
 * bufferevent. It first checks if the TCP multiplexing flag is set. If not, it
 * returns immediately. Otherwise, it prepares a TCP multiplexing header, encodes
 * the provided data into the header, and writes the header to the bufferevent.
 *
 * @param bout The bufferevent to write the data to.
 * @param flags Flags indicating the status or type of the data.
 * @param stream_id The ID of the stream to which the data belongs.
 * @param length The length of the data to be sent.
 */
void tcp_mux_send_data(struct bufferevent *bout, uint16_t flags,
                       uint32_t stream_id, uint32_t length) {
    // Early return if TCP multiplexing is disabled
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    // Validate input parameters
    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for sending data");
        return;
    }

    // Prepare and send header
    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(DATA, flags, stream_id, length, &tmux_hdr);
    
    if (bufferevent_write(bout, &tmux_hdr, sizeof(tmux_hdr)) < 0) {
        debug(LOG_ERR, "Failed to send data header for stream %u", stream_id);
    }
}

/**
 * @brief Sends a ping message over a TCP connection.
 *
 * This function constructs a TCP mux header for a ping message and writes it
 * to the specified bufferevent. The ping message is only sent if the tcp_mux_flag
 * function returns true.
 *
 * @param bout A pointer to the bufferevent to write the ping message to.
 * @param ping_id The identifier for the ping message.
 */
/**
 * @brief Sends a ping message over a TCP multiplexed connection
 *
 * This function constructs and sends a ping message with the SYN flag set
 * if TCP multiplexing is enabled. The ping message includes a unique ping ID
 * for tracking responses.
 *
 * @param bout The bufferevent to send the ping through
 * @param ping_id Unique identifier for this ping message
 * 
 * @note Function silently returns if TCP multiplexing is disabled
 *       or if bufferevent is invalid
 */
void tcp_mux_send_ping(struct bufferevent *bout, uint32_t ping_id) {
    // Early return if TCP multiplexing is disabled
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    // Validate bufferevent
    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for ping");
        return;
    }

    // Prepare and send ping message
    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(PING, SYN, 0, ping_id, &tmux_hdr);
    
    if (bufferevent_write(bout, &tmux_hdr, sizeof(tmux_hdr)) < 0) {
        debug(LOG_ERR, "Failed to send ping message");
    }
}

/**
 * @brief Handles a ping request in the TCP multiplexer.
 *
 * This function checks if the TCP multiplexer flag is set. If the flag is not set,
 * the function returns immediately. Otherwise, it prepares a TCP multiplexer header
 * for a ping acknowledgment and writes it to the provided buffer event.
 *
 * @param bout The buffer event to write the ping acknowledgment to.
 * @param ping_id The identifier of the ping request.
 */
/**
 * @brief Handles TCP multiplexer ping messages by sending an acknowledgment.
 *
 * This function responds to ping messages with a ping acknowledgment (ACK).
 * It validates input parameters and TCP multiplexing status before sending
 * the response.
 *
 * @param bout The bufferevent to write the ping acknowledgment to
 * @param ping_id The ID of the ping message to acknowledge
 *
 * @note The function will silently return if TCP multiplexing is disabled
 *       or if the bufferevent is invalid
 */
static void tcp_mux_handle_ping(struct bufferevent *bout, uint32_t ping_id) {
    // Early return if TCP multiplexing is disabled
    if (!tcp_mux_flag()) {
        debug(LOG_DEBUG, "TCP multiplexing is disabled");
        return;
    }

    // Validate bufferevent
    if (!bout) {
        debug(LOG_ERR, "Invalid bufferevent for ping response");
        return;
    }

    // Prepare and send ping acknowledgment
    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(PING, ACK, 0, ping_id, &tmux_hdr);
    
    if (bufferevent_write(bout, &tmux_hdr, sizeof(tmux_hdr)) < 0) {
        debug(LOG_ERR, "Failed to send ping acknowledgment");
    }
}

/**
 * @brief Sends a GO_AWAY message using the provided bufferevent.
 *
 * This function constructs a GO_AWAY message and sends it through the specified
 * bufferevent. The message is sent only if the tcp_mux_flag() returns true.
 *
 * @param bout The bufferevent through which the GO_AWAY message will be sent.
 * @param reason The reason code to be included in the GO_AWAY message.
 */
static void tcp_mux_send_go_away(struct bufferevent *bout, uint32_t reason) {
    // Early return if TCP multiplexing is disabled or buffer event is invalid
    if (!tcp_mux_flag() || !bout) {
        debug(LOG_ERR, "Cannot send GO_AWAY: invalid state or parameters");
        return;
    }

    // Validate reason code
    if (reason > INTERNAL_ERR) {
        debug(LOG_WARNING, "Invalid GO_AWAY reason code: %u", reason);
        reason = INTERNAL_ERR;
    }

    // Prepare and send header
    struct tcp_mux_header tmux_hdr;
    memset(&tmux_hdr, 0, sizeof(tmux_hdr));
    tcp_mux_encode(GO_AWAY, 0, 0, reason, &tmux_hdr);
    
    if (bufferevent_write(bout, &tmux_hdr, sizeof(tmux_hdr)) < 0) {
        debug(LOG_ERR, "Failed to send GO_AWAY message");
    }
}

/**
 * @brief Processes the given flags and updates the state of the tmux stream accordingly.
 *
 * This function handles the ACK, FIN, and RST flags and transitions the state of the 
 * tmux stream based on the current state and the received flags. It also handles the 
 * closing of the stream if necessary.
 *
 * @param flags The flags to process.
 * @param stream The tmux stream to update.
 * @return Returns 1 on success, 0 on failure.
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
            default:
                debug(LOG_ERR, "unexpected FIN flag in state %d", stream->state);
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
 *
 * This function determines the appropriate flags to be sent based on the 
 * current state of the given tmux_stream. It also updates the state of the 
 * stream accordingly.
 *
 * @param stream A pointer to the tmux_stream structure.
 * @return A uint16_t value representing the flags to be sent.
 */
static uint16_t get_send_flags(struct tmux_stream *stream) {
    uint16_t flags = 0;

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
 * @brief Sends a window update message for stream flow control
 *
 * Updates the receive window for a stream and sends a window update message if needed.
 * Window update is sent when either:
 * - The window delta exceeds half of max window size
 * - There are other flags that need to be sent
 *
 * @param bout Buffered output event for sending data
 * @param stream Pointer to the tmux stream to update
 * @param length Current receive buffer length
 * 
 * @note Window size cannot exceed MAX_STREAM_WINDOW_SIZE
 */
/**
 * @brief Sends a window update message for stream flow control.
 *
 * Updates the receive window for a stream and sends a window update message
 * if the delta exceeds half of the maximum window size or if there are flags to send.
 *
 * @param bout Buffered output event for sending data.
 * @param stream Pointer to the tmux stream to update.
 * @param length Current receive buffer length.
 */
void send_window_update(struct bufferevent *bout, struct tmux_stream *stream, uint32_t length) {
    const uint32_t max_window = MAX_STREAM_WINDOW_SIZE;
    const uint32_t half_max_window = max_window / 2;
    uint32_t delta = max_window > (length + stream->recv_window) 
                     ? max_window - length - stream->recv_window 
                     : 0;
    uint16_t flags = get_send_flags(stream);

    if (delta < half_max_window && flags == 0) {
        return;
    }

    stream->recv_window = MIN(stream->recv_window + delta, max_window);
    tcp_mux_send_win_update(bout, flags, stream->id, delta);
}

/**
 * Pops data from a ring buffer.
 * 
 * @param ring  Pointer to the ring buffer structure to pop from
 * @param data  Pointer to buffer where popped data will be stored
 * @param len   Number of bytes to pop from the ring buffer
 * 
 * @pre   ring->sz must be >= len
 * @pre   data pointer must not be NULL
 * 
 * @return The number of bytes popped from the buffer (equal to len)
 *
 * This function removes len bytes from the ring buffer and copies them
 * to the provided data buffer. The ring buffer's current position and size
 * are updated accordingly. When reaching the end of the buffer, it wraps
 * around to the beginning.
 */
int rx_ring_buffer_pop(struct ring_buffer *ring, uint8_t *data, uint32_t len) {
    assert(ring->sz >= len);
    assert(data);

    uint32_t remaining = len;
    uint8_t *dst = data;

    while (remaining > 0) {
        uint32_t chunk = MIN(remaining, RBUF_SIZE - ring->cur);
        memcpy(dst, &ring->data[ring->cur], chunk);
        dst += chunk;
        ring->cur = (ring->cur + chunk) % RBUF_SIZE;
        ring->sz -= chunk;
        remaining -= chunk;
    }

    return len;
}

/**
 * @brief Processes data received from a tmux stream
 *
 * This function handles data received from a multiplexed stream, managing window size
 * and forwarding data to appropriate handlers based on proxy type.
 *
 * @param stream Pointer to the tmux_stream structure containing stream information
 * @param length Length of data to be processed
 * @param flags Stream control flags
 * @param fn Callback function to handle processed data
 * @param param Additional parameters (typically proxy client structure)
 *
 * @return Returns length of processed data on success, 0 on failure
 *
 * The function performs the following operations:
 * - Validates stream and flags
 * - Checks receive window capacity
 * - Updates receive window size
 * - Handles data forwarding based on proxy type:
 *   - Regular proxy: Uses provided callback function
 *   - SOCKS5 proxy: Forwards to SOCKS5 client
 *   - Local proxy: Writes to local proxy bufferevent
 * - Sends window update after processing
 */
static int process_data(struct tmux_stream *stream, uint32_t length,
                        uint16_t flags, void (*handle_fn)(uint8_t *, int, void *),
                        void *param) {
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

    if (!pc || (!pc->local_proxy_bev && !is_socks5_proxy(pc->ps))) {
        uint8_t *data = calloc(length, sizeof(uint8_t));
        if (!data) {
            debug(LOG_ERR, "Memory allocation failed for data buffer");
            return 0;
        }

        bytes_processed = rx_ring_buffer_pop(&stream->rx_ring, data, length);
        handle_fn(data, bytes_processed, pc);
        free(data);
    } 
    else if (is_socks5_proxy(pc->ps)) {
        bytes_processed = handle_ss5(pc, &stream->rx_ring, length);
    } 
    else {
        bytes_processed = tx_ring_buffer_write(pc->local_proxy_bev, 
                                              &stream->rx_ring, 
                                              length);
    }

    if (bytes_processed != length) {
        debug(LOG_INFO, "Incomplete data transfer - processed: %u, expected: %u",
              bytes_processed, length);
    }

    struct bufferevent *bout = get_main_control()->connect_bev;
    send_window_update(bout, stream, bytes_processed);

    return length;
}

/**
 * @brief Increases the send window of a multiplexed TCP stream.
 *
 * This function handles the send window increment for a TCP multiplexed stream.
 * It processes the flags, validates the stream exists, and updates its send window.
 * When the send window transitions from 0, it re-enables read events on the buffer.
 *
 * @param bev The bufferevent associated with the connection
 * @param tmux_hdr Pointer to the TCP multiplexer header containing length info
 * @param flags The flags from the TCP multiplexer header
 * @param stream Pointer to the stream to update
 *
 * @return 1 on successful window increment, 0 on invalid stream or failed flag processing
 */
static int incr_send_window(struct bufferevent *bev,
                            struct tcp_mux_header *tmux_hdr, uint16_t flags,
                            struct tmux_stream *stream) {
    // Validate input parameters
    if (!bev || !tmux_hdr || !stream) {
        debug(LOG_ERR, "Invalid parameters in incr_send_window");
        return 0;
    }

    // Save stream ID for later use
    uint32_t stream_id = stream->id;

    // Process control flags first
    if (!process_flags(flags, stream)) {
        debug(LOG_ERR, "Failed to process flags for stream %d", stream_id);
        return 0;
    }

    // Verify stream still exists after flag processing
    if (!get_stream_by_id(stream_id)) {
        debug(LOG_DEBUG, "Stream %d no longer exists", stream_id);
        return 1;
    }

    // Get window increment size
    uint32_t increment = ntohl(tmux_hdr->length);

    // Enable read events if window was previously full
    if (stream->send_window == 0) {
        debug(LOG_DEBUG, "Enabling read events for stream %d", stream_id);
        bufferevent_enable(bev, EV_READ);
    }

    // Update send window
    stream->send_window += increment;
    debug(LOG_DEBUG, "Stream %d send window increased by %u to %u", 
          stream_id, increment, stream->send_window);

    return 1;
}

/**
 * @brief Handles incoming stream requests
 *
 * Processes new incoming stream requests identified by stream_id. If local_go_away
 * is set, sends a window update reset message and rejects the stream. Otherwise,
 * creates a new stream (TODO implementation).
 *
 * @param stream_id The unique identifier for the incoming stream
 * @return 0 if stream is rejected due to local_go_away, 1 if stream should be created
 */
static int incoming_stream(uint32_t stream_id) {
    if (local_go_away) {
        struct bufferevent *bout = get_main_control()->connect_bev;
        tcp_mux_send_win_update_rst(bout, stream_id);
        return 0;
    }

    // TODO
    // create new stream
    return 1;
}

/**
 * @brief Handles TCP multiplexer ping messages
 * 
 * This function processes incoming TCP multiplexer ping headers. If the SYN flag
 * is set in the header flags, it retrieves the main control connection's bufferevent
 * and handles the ping with the specified ping ID.
 *
 * @param tmux_hdr Pointer to the TCP multiplexer header structure containing
 *                 the ping message information
 * 
 * @note The ping_id and flags are converted from network to host byte order
 *       before processing
 */
/**
 * @brief Handles TCP multiplexer ping messages
 * 
 * Processes incoming TCP multiplexer ping messages and sends appropriate responses.
 * When a SYN flag is received in the ping message, it sends back a ping acknowledgment
 * to maintain connection liveliness.
 *
 * @param tmux_hdr Pointer to the TCP multiplexer header containing ping information
 *
 * @note Only responds to pings with SYN flag set
 * @note Ping ID is converted from network byte order before processing
 */
void handle_tcp_mux_ping(struct tcp_mux_header *tmux_hdr) {
    if (!tmux_hdr) {
        debug(LOG_ERR, "Invalid TCP MUX header");
        return;
    }

    struct bufferevent *bout = NULL;
    uint16_t flags = ntohs(tmux_hdr->flags);
    uint32_t ping_id = ntohl(tmux_hdr->length);

    // Only handle ping messages with SYN flag
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
 * 
 * Processes "go away" messages received from the remote TCP multiplexer based on
 * provided error codes. Sets appropriate flags and logs error messages depending
 * on the specific error code received.
 *
 * @param tmux_hdr Pointer to the TCP multiplexer header structure containing
 *                 the "go away" message details
 *
 * Error codes handled:
 * - NORMAL: Sets remote_go_away flag
 * - PROTO_ERR: Logs protocol error
 * - INTERNAL_ERR: Logs internal error
 * - Other codes: Logs unexpected error
 */
void handle_tcp_mux_go_away(struct tcp_mux_header *tmux_hdr) {
    if (!tmux_hdr) {
        debug(LOG_ERR, "Invalid TCP MUX header");
        return;
    }

    uint32_t code = ntohl(tmux_hdr->length);
    const char *error_msg = NULL;

    // Map error codes to messages
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

    // Log the appropriate error message with the error code
    if (code != NORMAL) {
        debug(LOG_ERR, "GO_AWAY received: %s (code=%u)", error_msg, code);
    } else {
        debug(LOG_INFO, "GO_AWAY received: %s", error_msg);
    }
}

/**
 * @brief Reads data from a bufferevent into a tmux stream's receive ring buffer
 * 
 * Reads up to the specified length of data from the given bufferevent into the 
 * stream's receive ring buffer. If the stream is not in ESTABLISHED state, a warning
 * will be logged but the read operation will still proceed.
 *
 * @param bev The bufferevent to read data from
 * @param stream Pointer to the tmux stream structure
 * @param len Maximum number of bytes to read
 * @return The actual number of bytes read into the stream's ring buffer
 *
 * @note The function will assert if stream parameter is NULL
 */
uint32_t tmux_stream_read(struct bufferevent *bev, struct tmux_stream *stream,
                          uint32_t len) {
    // Validate input parameters
    if (!bev || !stream || len == 0) {
        debug(LOG_ERR, "Invalid parameters passed to tmux_stream_read");
        return 0;
    }

    // Check stream state
    if (stream->state != ESTABLISHED) {
        debug(LOG_WARNING,
              "Stream %d is in state %d (not ESTABLISHED). Reading %d bytes anyway.",
              stream->id, stream->state, len);
    }

    // Perform the actual read operation
    uint32_t bytes_read = rx_ring_buffer_read(bev, &stream->rx_ring, len);

    // Log read operation result if debug is enabled
    if (bytes_read < len) {
        debug(LOG_DEBUG, "Stream %d: Read %u bytes (requested %u)",
              stream->id, bytes_read, len);
    }

    return bytes_read;
}

/**
 * @brief Handles TCP multiplexing stream data and control messages
 *
 * This function processes incoming TCP multiplexing stream packets, handling different
 * types of messages including data transfer and window updates. It manages stream states
 * and ensures proper protocol flow.
 *
 * @param tmux_hdr Pointer to the TCP multiplexing header structure containing packet information
 * @param fn Callback function for handling stream data
 *
 * @return Returns the length of processed data on success, 0 on failure or when no data needs processing
 *
 * @note This function expects to be called from the client (xfrpc) side and will log a warning
 *       if it receives unexpected SYN flags
 *
 * The function performs the following:
 * - Validates stream existence and state
 * - Handles window update messages
 * - Processes data streams in ESTABLISHED state
 * - Manages protocol errors by sending GO_AWAY messages when necessary
 */
int handle_tcp_mux_stream(struct tcp_mux_header *tmux_hdr,
                          handle_data_fn_t fn) {
    if (!tmux_hdr || !fn) {
        return 0;
    }

    uint32_t stream_id = ntohl(tmux_hdr->stream_id);
    uint16_t flags = ntohs(tmux_hdr->flags);

    // Handle incoming SYN packets (unexpected for xfrpc client)
    if ((flags & SYN) == SYN) {
        debug(LOG_INFO, "Unexpected SYN flag received for stream %d in xfrpc", stream_id);
        return incoming_stream(stream_id) ? 0 : 0;
    }

    // Validate stream exists
    struct tmux_stream *stream = get_stream_by_id(stream_id);
    if (!stream) {
        debug(LOG_ERR, "Stream %d not found", stream_id);
        return 0;
    }

    struct proxy_client *pc = get_proxy_client(stream_id);
    struct bufferevent *bout = get_main_control()->connect_bev;

    // Handle window updates
    if (tmux_hdr->type == WINDOW_UPDATE) {
        if (!incr_send_window(bout, tmux_hdr, flags, stream)) {
            debug(LOG_ERR, "Protocol error while handling window update");
            tcp_mux_send_go_away(bout, PROTO_ERR);
        }
        return 0;
    }

    // Verify stream state
    if (stream->state != ESTABLISHED) {
        debug(LOG_ERR, "Stream %d not in ESTABLISHED state", stream_id);
        return 0;
    }

    // Process data
    int32_t length = ntohl(tmux_hdr->length);
    if (!process_data(stream, length, flags, fn, (void *)pc)) {
        debug(LOG_ERR, "Protocol error while processing data");
        tcp_mux_send_go_away(bout, PROTO_ERR);
        return 0;
    }

    return length;
}

/**
 * @brief Appends data to a ring buffer
 *
 * This function adds data to a ring buffer in a circular fashion. It handles buffer
 * wraparound when the end is reached. The function will stop appending if it catches
 * up with the current read position (cur).
 *
 * @param ring Pointer to the ring buffer structure
 * @param data Pointer to the data to be appended
 * @param len Length of data to append
 *
 * @pre len must be less than or equal to available space (WBUF_SIZE - ring->sz)
 * 
 * @return Number of bytes actually appended to the ring buffer
 */
static int tx_ring_buffer_append(struct ring_buffer *ring, uint8_t *data, uint32_t len) {
    // Validate inputs and capacity
    if (!ring || !data || len == 0) {
        return 0;
    }

    uint32_t available_space = WBUF_SIZE - ring->sz;
    if (available_space < len) {
        return 0;
    }

    uint32_t bytes_written = 0;
    while (bytes_written < len) {
        // Calculate contiguous space until buffer wrap
        uint32_t contiguous_space = MIN(len - bytes_written, 
                                      WBUF_SIZE - ring->end);
        
        // Copy block of data
        memcpy(&ring->data[ring->end], 
               &data[bytes_written], 
               contiguous_space);
        
        // Update ring buffer state
        ring->end = (ring->end + contiguous_space) % WBUF_SIZE;
        ring->sz += contiguous_space;
        bytes_written += contiguous_space;

        // Stop if we've caught up with read pointer
        if (ring->cur == ring->end) {
            break;
        }
    }

    return bytes_written;
}

/**
 * @brief Reads data from a bufferevent into a ring buffer
 *
 * This function reads data from the given bufferevent into the ring buffer up to the specified length,
 * handling buffer wrap-around and capacity limits.
 *
 * @param bev The bufferevent to read data from
 * @param ring Pointer to the ring buffer structure to store data
 * @param len The number of bytes to attempt to read
 *
 * @return The actual number of bytes read (may be less than len if buffer capacity is reached)
 *         Returns 0 if the ring buffer is already full
 *
 * @note Reading stops if the end pointer catches up to the current position (cur)
 *       The function handles wrap-around when end reaches RBUF_SIZE
 */
uint32_t rx_ring_buffer_read(struct bufferevent *bev, struct ring_buffer *ring,
                             uint32_t len) {
    // Check if buffer is full
    if (ring->sz == RBUF_SIZE) {
        debug(LOG_ERR, "ring buffer is full");
        return 0;
    }

    // Calculate available capacity and adjust length if needed
    uint32_t available_space = RBUF_SIZE - ring->sz;
    uint32_t bytes_to_read = MIN(len, available_space);
    uint32_t bytes_read = 0;

    while (bytes_read < bytes_to_read) {
        // Calculate contiguous space until buffer wrap
        uint32_t contiguous_space = MIN(bytes_to_read - bytes_read, 
                                      RBUF_SIZE - ring->end);
        
        // Read a block of contiguous data
        uint32_t n = bufferevent_read(bev, 
                                    &ring->data[ring->end], 
                                    contiguous_space);
        
        ring->end = (ring->end + n) % RBUF_SIZE;
        ring->sz += n;
        bytes_read += n;

        // Stop if we've caught up with read pointer
        if (ring->cur == ring->end) {
            break;
        }
    }

    return bytes_read;
}

/**
 * @brief Writes data from a ring buffer to a bufferevent
 *
 * This function writes up to 'len' bytes from the ring buffer to the specified bufferevent.
 * It handles buffer wrapping at WBUF_SIZE boundary and updates ring buffer state accordingly.
 *
 * @param bev The bufferevent to write data to
 * @param ring Pointer to the ring buffer structure containing the data
 * @param len Maximum number of bytes to write
 *
 * @return The actual number of bytes written. Returns 0 if the ring buffer is empty.
 *         Otherwise returns the number of bytes successfully written, which may be
 *         less than or equal to len depending on available data in ring buffer.
 *
 * @note The function writes one byte at a time and handles buffer wraparound.
 *       It will stop writing if it reaches the end marker of the ring buffer.
 */
uint32_t tx_ring_buffer_write(struct bufferevent *bev, struct ring_buffer *ring,
                              uint32_t len) {
    // Check for empty buffer
    if (ring->sz == 0) {
        debug(LOG_ERR, "ring buffer is empty");
        return 0;
    }

    // Adjust length if it exceeds available data
    len = MIN(len, ring->sz);

    uint32_t bytes_to_write = len;
    uint32_t contiguous_bytes;

    while (bytes_to_write > 0) {
        // Calculate contiguous bytes available until buffer wrap or end
        contiguous_bytes = MIN(bytes_to_write, WBUF_SIZE - ring->cur);
        
        // Write contiguous block of data
        bufferevent_write(bev, &ring->data[ring->cur], contiguous_bytes);
        
        // Update ring buffer state
        ring->cur = (ring->cur + contiguous_bytes) % WBUF_SIZE;
        ring->sz -= contiguous_bytes;
        bytes_to_write -= contiguous_bytes;

        // Check if we've reached the end marker
        if (ring->cur == ring->end) {
            assert(ring->sz == 0);
            break;
        }
    }

    return len - bytes_to_write;
}

/**
 * @brief Writes data to a TCP multiplexing stream with flow control
 *
 * This function handles writing data to a TCP multiplexing stream while managing
 * flow control through send windows and buffering. It handles different stream
 * states and buffer conditions.
 *
 * @param bev The bufferevent structure for writing data
 * @param data Pointer to the data buffer to be written
 * @param length Length of the data to be written
 * @param stream Pointer to the tmux_stream structure containing stream state and buffers
 *
 * @return uint32_t Number of bytes processed (may be 0 if stream is closed or window is full)
 *
 * The function handles several cases:
 * - Returns 0 if stream is in CLOSED, LOCAL_CLOSE, or RESET state
 * - Buffers data if send window is 0
 * - Manages partial writes based on available send window size
 * - Handles buffered data in tx_ring along with new data
 *
 * Flow control is maintained through the stream's send_window, which is decremented
 * by the number of bytes processed.
 */
uint32_t tmux_stream_write(struct bufferevent *bev, uint8_t *data,
                           uint32_t length, struct tmux_stream *stream) {
    // Check if the stream is in a closed state
    if (stream->state == LOCAL_CLOSE || stream->state == CLOSED || stream->state == RESET) {
        debug(LOG_INFO, "stream %d state is closed", stream->id);
        return 0;
    }

    struct ring_buffer *tx_ring = &stream->tx_ring;
    uint32_t available_window = stream->send_window;
    uint32_t buffered_size = tx_ring->sz;
    uint32_t total_data_size = buffered_size + length;

    // If send window is zero, buffer the data
    if (available_window == 0) {
        debug(LOG_INFO, "stream %d send_window is zero, buffering data", stream->id);
        tx_ring_buffer_append(tx_ring, data, length);
        return 0;
    }

    uint16_t flags = get_send_flags(stream);
    struct bufferevent *bout = get_main_control()->connect_bev;

    // Determine how much data we can send
    uint32_t max_send = (available_window < total_data_size) ? available_window : total_data_size;

    // Send data header
    tcp_mux_send_data(bout, flags, stream->id, max_send);

    // Send data from tx_ring buffer if any
    if (buffered_size > 0) {
        uint32_t send_from_buffer = (max_send < buffered_size) ? max_send : buffered_size;
        tx_ring_buffer_write(bev, tx_ring, send_from_buffer);
        max_send -= send_from_buffer;
    }

    // Send new data if there is remaining window
    if (max_send > 0) {
        bufferevent_write(bev, data, max_send);
    }

    // Buffer any remaining new data
    if (total_data_size > available_window) {
        uint32_t remaining_data = total_data_size - available_window;
        tx_ring_buffer_append(tx_ring, data + (length - remaining_data), remaining_data);
    }

    // Update send window
    stream->send_window -= (total_data_size - tx_ring->sz);

    return (length - tx_ring->sz);
}

/**
 * Handles the closure of a TCP multiplexing stream.
 *
 * This function manages the state transition during stream closure and sends
 * appropriate flags to the remote peer. It handles different states of the stream
 * including SYN_SEND, SYN_RECEIVED, ESTABLISHED, LOCAL_CLOSE, REMOTE_CLOSE,
 * CLOSED, and RESET.
 *
 * @param bout The bufferevent used for sending data
 * @param stream The tmux_stream structure to be closed
 *
 * @return Returns:
 *         - 0 if stream is already closed/reset or final closure is complete
 *         - 1 if stream entered LOCAL_CLOSE state but final closure is pending
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

    uint16_t flags = get_send_flags(stream) | FIN;
    tcp_mux_send_win_update(bout, flags, stream->id, 0);

    if (!should_close) {
        return 1;
    }

    debug(LOG_DEBUG, "del proxy client %d", stream->id);
    del_proxy_client_by_stream_id(stream->id);
    return 0;
}
