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
	ACK,
	FIN,
	RST,
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


struct __attribute__((__packed__)) tcp_mux_header {
	uint8_t		version;
	uint8_t		type;
	uint16_t	flags;
	uint32_t	stream_id;
	uint32_t	length;
};

void tcp_mux_send_win_update_syn(struct bufferevent *bout, uint32_t stream_id);

void tcp_mux_send_win_update_rst(struct bufferevent *bout, uint32_t stream_id);

void tcp_mux_send_data(struct bufferevent *bout, uint32_t stream_id, uint32_t length);

void tcp_mux_send_ping(struct bufferevent *bout, uint32_t ping_id);

uint32_t get_next_session_id();

void tcp_mux_encode(enum tcp_mux_type type, enum tcp_mux_flag flags, uint32_t stream_id, uint32_t length, struct tcp_mux_header *tmux_hdr);

void handle_tcp_mux_frps_msg(uint8_t *data, int len, void (*fn)(uint8_t *, int, void *));

#endif
