// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_TCPMUX_H
#define XFRPC_TCPMUX_H

#include "uthash.h"
#include <stdint.h>

#define MAX_STREAM_WINDOW_SIZE (8 * 1024 * 1024)  // 8MB to match frps server
#define MAX_YAMUX_WINDOW_SIZE  (6 * 1024 * 1024)  // 6MB to match frps MaxStreamWindowSize
#define DEFAULT_MAX_FRAME_SIZE (32 * 1024)         // 32KB max frame size (matches yamux/smux)

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
    char *desc;
};

enum tcp_mux_flag {
    ZERO,
    SYN,
    ACK = 1 << 1,
    FIN = 1 << 2,
    RST = 1 << 3,
};

struct __attribute__((__packed__)) tcp_mux_header {
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t stream_id;
    uint32_t length;
};

struct tcp_mux_flag_desc {
    enum tcp_mux_flag flag;
    char *desc;
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
    uint32_t id;
    uint32_t recv_window;
    uint32_t send_window;
    enum tcp_mux_state state;

    // private arguments
    UT_hash_handle hh;
};

typedef void (*handle_data_fn_t)(uint8_t *, int, void *);

/**
 * @brief Initializes TCP MUX stream.
 */
void init_tmux_stream(struct tmux_stream *stream, uint32_t id,
                      enum tcp_mux_state state);

/**
 * @brief Validates a TCP MUX protocol.
 */
int validate_tcp_mux_protocol(struct tcp_mux_header *tmux_hdr);

/**
 * @brief Sends window update message.
 */
void send_window_update(struct bufferevent *bout, struct tmux_stream *stream,
                        uint32_t length);

/**
 * @brief Sends a TCP MUX window update message with SYN flag.
 */
void tcp_mux_send_win_update_syn(struct bufferevent *bout, uint32_t stream_id);

/**
 * @brief Sends a TCP MUX window update message with ACK flag.
 */
void tcp_mux_send_win_update_ack(struct bufferevent *bout, uint32_t stream_id,
                                 uint32_t delta);

/**
 * @brief Sends a TCP MUX window update message with FIN flag.
 */
void tcp_mux_send_win_update_fin(struct bufferevent *bout, uint32_t stream_id);

/**
 * @brief Sends a TCP MUX window update message with RST flag.
 */
void tcp_mux_send_win_update_rst(struct bufferevent *bout, uint32_t stream_id);

/**
 * @brief Sends a TCP MUX data message.
 */
void tcp_mux_send_data(struct bufferevent *bout, enum tcp_mux_flag flags,
                       uint32_t stream_id, uint32_t length);

/**
 * @brief Sends a TCP MUX ping message.
 */
void tcp_mux_send_ping(struct bufferevent *bout, uint32_t ping_id);

/**
 * @brief get the next session ID.
 */
uint32_t get_next_session_id();

/**
 * @brief Encodes a TCP MUX header.
 */
void tcp_mux_encode(enum tcp_mux_type type, enum tcp_mux_flag flags,
                    uint32_t stream_id, uint32_t length,
                    struct tcp_mux_header *tmux_hdr);

/**
 * @brief Handles a TCP MUX data stream (window updates).
 */
int handle_tcp_mux_stream(struct tcp_mux_header *tmux_hdr, handle_data_fn_t fn);

/**
 * @brief Handles a TCP MUX ping message.
 */
void handle_tcp_mux_ping(struct tcp_mux_header *tmux_hdr);

/**
 * @brief Handles a TCP MUX go away message.
 */
void handle_tcp_mux_go_away(struct tcp_mux_header *tmux_hdr);

/**
 * @brief Writes data to a tmux stream with flow control.
 *
 * @return Positive: bytes written. 0: backpressure (send_window==0). Negative: error.
 */
int tmux_stream_write(struct bufferevent *bev, uint8_t *data,
                      uint32_t length, struct tmux_stream *stream);

/**
 * @brief Resets the session ID counter.
 */
void reset_session_id();

/**
 * @brief Retrieves the current tmux stream.
 */
struct tmux_stream *get_cur_stream();

/**
 * @brief Sets the current tmux stream.
 */
void set_cur_stream(struct tmux_stream *stream);

/**
 * @brief Adds a tmux stream to the stream list.
 */
void add_stream(struct tmux_stream *stream);

/**
 * @brief Deletes a tmux stream by its ID.
 */
void del_stream(uint32_t stream_id);

/**
 * @brief Clears all tmux streams from the stream list.
 */
void clear_stream();

/**
 * @brief Retrieves a tmux stream by its ID.
 */
struct tmux_stream *get_stream_by_id(uint32_t id);

/**
 * @brief Closes a tmux stream.
 */
int tmux_stream_close(struct bufferevent *bout, struct tmux_stream *stream);

/**
 * @brief Processes data from a tmux DATA frame and dispatches to protocol handlers.
 *
 * Reads the payload from the control bev and dispatches it to the appropriate
 * protocol handler (SOCKS5, XDPI, default callback, or direct local forwarding).
 *
 * @param bev    The control bufferevent to read payload from.
 * @param stream The tmux stream for this frame.
 * @param length Length of the DATA payload to consume.
 * @param flags  Frame flags (may carry FIN/RST).
 * @param fn     Default callback handler.
 * @param param  Callback context (proxy_client).
 * @return Length of processed data on success, 0 on failure.
 */
int process_data(struct bufferevent *bev, struct tmux_stream *stream,
                 uint32_t length, uint16_t flags,
                 void (*handle_fn)(uint8_t *, int, void *), void *param);

#endif
