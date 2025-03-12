
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_TCPMUX_H
#define XFRPC_TCPMUX_H

#include "uthash.h"
#include <stdint.h>

#define MAX_STREAM_WINDOW_SIZE (256 * 1024)
#define RBUF_SIZE (32 * 1024)
#define WBUF_SIZE (32 * 1024)

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
    struct ring_buffer tx_ring;
    struct ring_buffer rx_ring;

    // private arguments
    UT_hash_handle hh;
};

typedef void (*handle_data_fn_t)(uint8_t *, int, void *);

/**
 * @brief Initializes TCP MUX stream.
 * 
 * @param stream Pointer to the tmux_stream structure.
 * @param id     Stream ID of the TCP MUX message.
 * @param state  State of the TCP MUX message.
 */
void init_tmux_stream(struct tmux_stream *stream, uint32_t id,
                      enum tcp_mux_state state);

/**
 * @brief Validates a TCP MUX protocol.
 * 
 * @param tmux_hdr Pointer to the TCP MUX header.
 * @return Status of the operation.
 */
int validate_tcp_mux_protocol(struct tcp_mux_header *tmux_hdr);

/**
 * @brief Sends window update message.
 * 
 * @param bout   The bufferevent to send the window update message.
 * @param stream Pointer to the tmux_stream structure.
 * @param length Length of the window update message.
 */
void send_window_update(struct bufferevent *bout, struct tmux_stream *stream,
                        uint32_t length);

/**
 * @brief Sends a TCP MUX window update message with SYN flag.
 * 
 * @param bout     The bufferevent to send the window update message.
 * @param stream_id Stream ID of the TCP MUX message.
 */
void tcp_mux_send_win_update_syn(struct bufferevent *bout, uint32_t stream_id);

/**
 * @brief Sends a TCP MUX window update message with ACK flag.
 * 
 * @param bout     The bufferevent to send the window update message.
 * @param stream_id Stream ID of the TCP MUX message.
 * @param delta    Delta of the TCP MUX message.
 */
void tcp_mux_send_win_update_ack(struct bufferevent *bout, uint32_t stream_id,
                                 uint32_t delta);

/**
 * @brief Sends a TCP MUX window update message with FIN flag.
 * 
 * @param bout     The bufferevent to send the window update message.
 * @param stream_id Stream ID of the TCP MUX message.
 */
void tcp_mux_send_win_update_fin(struct bufferevent *bout, uint32_t stream_id);

/**
 * @brief Sends a TCP MUX window update message with RST flag.
 * 
 * @param bout     The bufferevent to send the window update message.
 * @param stream_id Stream ID of the TCP MUX message.
 */
void tcp_mux_send_win_update_rst(struct bufferevent *bout, uint32_t stream_id);

/**
 * @brief Sends a TCP MUX data message.
 * 
 * @param bout     The bufferevent to send the data message.
 * @param flags    Flags of the TCP MUX message.
 * @param stream_id Stream ID of the TCP MUX message.
 * @param length   Length of the TCP MUX message.
 */
void tcp_mux_send_data(struct bufferevent *bout, uint16_t flags,
                       uint32_t stream_id, uint32_t length);

/**
 * @brief Sends a TCP MUX ping message.
 * 
 * @param bout   The bufferevent to send the ping message.
 * @param ping_id The ping ID to send.
 */
void tcp_mux_send_ping(struct bufferevent *bout, uint32_t ping_id);

/**
 * @brief get the next session ID.
 */
uint32_t get_next_session_id();

/**
 * @brief Encodes a TCP MUX header.
 *
 * @param type     Type of the TCP MUX message.
 * @param flags    Flags of the TCP MUX message.
 * @param stream_id Stream ID of the TCP MUX message.
 * @param length   Length of the TCP MUX message.
 * @param tmux_hdr Pointer to the TCP MUX header.
 */
void tcp_mux_encode(enum tcp_mux_type type, enum tcp_mux_flag flags,
                    uint32_t stream_id, uint32_t length,
                    struct tcp_mux_header *tmux_hdr);

/**
 * @brief Handles a TCP MUX data stream.
 *
 * @param tmux_hdr Pointer to the TCP MUX header.
 * @param fn       Function pointer to handle the data.
 * @return Status of the operation.
 */
int handle_tcp_mux_stream(struct tcp_mux_header *tmux_hdr, handle_data_fn_t fn);

/**
 * @brief Handles a TCP MUX ping message.
 *
 * @param tmux_hdr Pointer to the TCP MUX header.
 */
void handle_tcp_mux_ping(struct tcp_mux_header *tmux_hdr);

/**
 * @brief Handles a TCP MUX go away message.
 *
 * @param tmux_hdr Pointer to the TCP MUX header.
 */
void handle_tcp_mux_go_away(struct tcp_mux_header *tmux_hdr);

/**
 * @brief Writes data to a tmux stream.
 *
 * @param bev    The bufferevent to write data to.
 * @param data   Pointer to the data buffer to write.
 * @param length Length of the data to write.
 * @param stream Pointer to the tmux_stream structure.
 * @return Number of bytes written.
 */
uint32_t tmux_stream_write(struct bufferevent *bev, uint8_t *data,
                           uint32_t length, struct tmux_stream *stream);

/**
 * @brief Reads data from a tmux stream.
 *
 * @param bev    The bufferevent to read data from.
 * @param stream Pointer to the tmux_stream structure.
 * @param len    Maximum number of bytes to read.
 * @return Number of bytes read.
 */
uint32_t tmux_stream_read(struct bufferevent *bev, struct tmux_stream *stream,
                          uint32_t len);

/**
 * @brief Resets the session ID counter.
 */
void reset_session_id();

/**
 * @brief Retrieves the current tmux stream.
 *
 * @return Pointer to the current tmux_stream.
 */
struct tmux_stream *get_cur_stream();

/**
 * @brief Sets the current tmux stream.
 *
 * @param stream Pointer to the tmux_stream to set as current.
 */
void set_cur_stream(struct tmux_stream *stream);

/**
 * @brief Adds a tmux stream to the stream list.
 *
 * @param stream Pointer to the tmux_stream to add.
 */
void add_stream(struct tmux_stream *stream);

/**
 * @brief Deletes a tmux stream by its ID.
 *
 * @param stream_id ID of the tmux_stream to delete.
 */
void del_stream(uint32_t stream_id);

/**
 * @brief Clears all tmux streams from the stream list.
 */
void clear_stream();

/**
 * @brief Retrieves a tmux stream by its ID.
 *
 * @param id ID of the tmux_stream to retrieve.
 * @return Pointer to the tmux_stream if found, NULL otherwise.
 */
struct tmux_stream *get_stream_by_id(uint32_t id);

/**
 * @brief Closes a tmux stream.
 *
 * @param bev    The bufferevent associated with the stream.
 * @param stream Pointer to the tmux_stream to close.
 * @return 0 on success, negative value on error.
 */
int tmux_stream_close(struct bufferevent *bout, struct tmux_stream *stream);

/**
 * @brief Pops data from the receive ring buffer.
 *
 * @param ring Pointer to the ring_buffer structure.
 * @param data Buffer to store the popped data.
 * @param len  Maximum number of bytes to pop.
 * @return Number of bytes popped.
 */
int rx_ring_buffer_pop(struct ring_buffer *ring, uint8_t *data, uint32_t len);


int rx_ring_buffer_peek(struct ring_buffer *ring, uint8_t *data, uint32_t len);

/**
 * @brief Reads data from a bufferevent into the receive ring buffer.
 *
 * @param bev  The bufferevent to read data from.
 * @param ring Pointer to the ring_buffer to store data.
 * @param len  Maximum number of bytes to read.
 * @return Number of bytes read.
 */
uint32_t rx_ring_buffer_read(struct bufferevent *bev, struct ring_buffer *ring,
                             uint32_t len);

/**
 * @brief Writes data from the transmit ring buffer to a bufferevent.
 *
 * @param bev  The bufferevent to write data to.
 * @param ring Pointer to the ring_buffer containing data to send.
 * @param len  Maximum number of bytes to write.
 * @return Number of bytes written.
 */
uint32_t tx_ring_buffer_write(struct bufferevent *bev, struct ring_buffer *ring,
                              uint32_t len);

#endif
