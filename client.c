// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <errno.h>
#include <syslog.h>
#include <zlib.h>


#include "debug.h"
#include "client.h"
#include "uthash.h"
#include "control.h"
#include "config.h"
#include "uthash.h"
#include "zip.h"
#include "common.h"
#include "proxy.h"
#include "utils.h"
#include "tcpmux.h"

static struct proxy_client 	*all_pc = NULL;

/**
 * @brief Event callback for worker connection events
 */
static void xfrp_worker_event_cb(struct bufferevent *bev, short what, void *ctx) {
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		debug(LOG_DEBUG, "Working connection closed");
		bufferevent_free(bev);
	}
}

/**
 * @brief Handles post-connection data sending for proxy clients
 *
 * After the local connection is established, flush any buffered parser data
 * and transition the protocol FSM to the established/forwarding state.
 */
static int handle_post_connection_data(struct proxy_client *client) {
	if (!client) return -1;

	struct common_conf *c_conf = get_common_config();

	if (is_socks5_proxy(client->ps)) {
		/* Flush any remaining SOCKS5 parser buffer to local proxy */
		if (client->socks5_buf && client->socks5_buf_len > 0 && client->local_proxy_bev) {
			bufferevent_write(client->local_proxy_bev,
				client->socks5_buf, client->socks5_buf_len);
			client->socks5_buf_len = 0;
		}

		/* Send SOCKS5 connect success reply: VER(05) REP(00) RSV(00) ATYP(01) ADDR(00000000) PORT(0000) */
		uint8_t success_reply[] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		if (!c_conf->tcp_mux) {
			bufferevent_write(client->ctl_bev, success_reply, sizeof(success_reply));
		} else {
			struct evbuffer *tmp = evbuffer_new();
			if (tmp) {
				evbuffer_add(tmp, success_reply, sizeof(success_reply));
				tmux_stream_write(client->ctl_bev, tmp, &client->stream);
				evbuffer_free(tmp);
			}
		}
		bufferevent_flush(client->ctl_bev, EV_WRITE, BEV_FLUSH);

		client->state = SOCKS5_ESTABLISHED;
		return 0;
	}

	/* Non-SOCKS5, non-XDPI: send any initial data from control message */
	if (client->data_tail_size > 0) {
		debug(LOG_DEBUG, "Sending pending client data (%zu bytes)", client->data_tail_size);
		return send_client_data_tail(client);
	}

	return 0;
}

/**
 * @brief Handles proxy client disconnection
 *
 * Flushes remaining data from the local proxy bufferevent into the MUX stream
 * before closing. Loops to handle partial sends when send_window is smaller
 * than remaining data.
 */
static void handle_proxy_disconnect(struct proxy_client *client, 
								  struct bufferevent *bev, 
								  const char *error_msg) {
	if (!client || !client->ps) return;

	debug(LOG_INFO, "Proxy close connection %s - stream_id %d: %s",
		  error_msg, client->stream_id, strerror(errno));

	/* Flush remaining data from the local proxy bufferevent into MUX stream.
	 * Loop to handle partial sends — tmux_stream_write drains
	 * what it writes directly from src when send_window allows. */
	if (bev && client->ctl_bev) {
		struct evbuffer *src = bufferevent_get_input(bev);
		struct common_conf *c_conf = get_common_config();
		if (!c_conf->tcp_mux) {
			struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
			evbuffer_add_buffer(dst, src);
		} else {
			while (evbuffer_get_length(src) > 0) {
				int written = tmux_stream_write(client->ctl_bev, src, &client->stream);
				if (written < 0) {
					debug(LOG_INFO, "Stream %d: tmux_stream_write error %d during flush, aborting",
						  client->stream.id, written);
					break;
				}
				if (written == 0) {
					/* send_window == 0: can't send more right now */
					debug(LOG_INFO, "%zu bytes unsent, send_window exhausted",
						  evbuffer_get_length(src));
					break;
				}
			}
		}
	}

	// Close the local proxy bufferevent
	if (bev) {
		bufferevent_free(bev);
		client->local_proxy_bev = NULL;
	}

	// If send_window is exhausted, mark as pending_close and wait for
	// WINDOW_UPDATE to send FIN.
	if (client->stream.send_window == 0) {
		debug(LOG_INFO, "Stream %d: send_window==0 at disconnect, deferring close",
			  client->stream.id);
		client->pending_close = 1;
		return;
	}

	// send_window available, close the stream immediately
	tmux_stream_close(client->ctl_bev, &client->stream);
}

/**
 * @brief Event callback for proxy connection events
 */
void xfrp_proxy_event_cb(struct bufferevent *bev, short what, void *ctx) {
	struct proxy_client *client = ctx;
	if (!client) {
		debug(LOG_ERR, "Invalid proxy client context");
		return;
	}

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		const char *error_msg;
		if (is_socks5_proxy(client->ps)) {
			error_msg = "socks5 proxy";
		} else {
			error_msg = "server";
		}
		handle_proxy_disconnect(client, bev, error_msg);
	} else if (what & BEV_EVENT_CONNECTED) {
		debug(LOG_DEBUG, "Client %d connected", client->stream_id);
		/* Set TCP_NODELAY on local proxy socket to reduce latency for
		 * interactive protocols (SOCKS5, SSH, RDP) and small-packet
		 * HTTP traffic.  Nagle's algorithm adds up to 40ms delay. */
		int fd = bufferevent_getfd(bev);
		if (fd >= 0) {
			int one = 1;
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
		}
		handle_post_connection_data(client);
	}
}

/**
 * @brief Check if proxy service is of a specific type
 */
static int is_proxy_type(const struct proxy_service *ps, const char *type, int extra_check) {
	if (!ps || !ps->proxy_type) {
		return 0;
	}
	return (strcmp(ps->proxy_type, type) == 0) && extra_check;
}

/**
 * @brief Check if proxy service is FTP type
 */
int is_ftp_proxy(const struct proxy_service *ps) {
	return is_proxy_type(ps, "ftp", ps->remote_data_port > 0);
}

/**
 * @brief Check if proxy service is SOCKS5 type
 */
int is_socks5_proxy(const struct proxy_service *ps) {
	return is_proxy_type(ps, "socks5", 1);
}

/**
 * @brief Check if proxy service has XDPI service type configured
 */
int has_service_type(const struct proxy_service *ps) {
	if (!ps) return 0;

	return ps->service_type != NO_XDPI;
}

/**
 * @brief Check if proxy service is UDP type
 */
int is_udp_proxy(const struct proxy_service *ps) {
	return is_proxy_type(ps, "udp", 1);
}

/**
 * @brief Check if proxy service is TCPMux type
 */
int is_tcpmux_proxy(const struct proxy_service *ps) {
	return is_proxy_type(ps, "tcpmux", 1);
}

/**
 * Check if proxy service is STCP type
 */
int is_stcp_proxy(const struct proxy_service *ps) {
	return is_proxy_type(ps, "stcp", 1);
}

/**
 * Check if proxy service uses Unix Domain Socket plugin
 */
int is_uds_proxy(const struct proxy_service *ps) {
	return (ps && ps->plugin && strcmp(ps->plugin, "unix_domain_socket") == 0 &&
		ps->plugin_unix_path != NULL);
}

/**
 * Sets up callback functions for a proxy client
 */
static void setup_proxy_callbacks(struct proxy_client *client, 
								bufferevent_data_cb *proxy_c2s_recv,
								bufferevent_data_cb *proxy_s2c_recv) 
{
	struct proxy_service *ps = client->ps;
	
	if (is_ftp_proxy(ps)) {
		*proxy_c2s_recv = ftp_proxy_c2s_cb;
		*proxy_s2c_recv = ftp_proxy_s2c_cb;
	} else if (is_udp_proxy(ps)) {
		*proxy_c2s_recv = udp_proxy_c2s_cb;
		*proxy_s2c_recv = udp_proxy_s2c_cb;
	} else if (is_socks5_proxy(ps)) {
		*proxy_c2s_recv = tcp_proxy_c2s_cb;
		*proxy_s2c_recv = socks5_proxy_s2c_cb;
	} else if (has_service_type(ps)) {
		*proxy_c2s_recv = tcp_proxy_c2s_cb;
		*proxy_s2c_recv = xdpi_proxy_s2c_cb;
	} else {
		*proxy_c2s_recv = tcp_proxy_c2s_cb;
		*proxy_s2c_recv = tcp_proxy_s2c_cb;
	}
}

/**
 * @brief Connect to a local Unix Domain Socket
 *
 * Creates a non-blocking connection to a Unix domain socket at the given path.
 * Returns a bufferevent connected to the socket, or NULL on failure.
 */
static struct bufferevent *connect_unix_server(struct event_base *base, const char *unix_path)
{
	if (!base || !unix_path) {
		debug(LOG_ERR, "Invalid parameters for Unix socket connection");
		return NULL;
	}

	/* Create Unix socket */
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		debug(LOG_ERR, "Failed to create Unix socket: %s", strerror(errno));
		return NULL;
	}

	/* Set non-blocking */
	evutil_make_socket_nonblocking(fd);

	/* Connect to Unix socket */
	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, unix_path, sizeof(sun.sun_path) - 1);

	int ret = connect(fd, (struct sockaddr *)&sun, sizeof(sun));
	if (ret < 0 && errno != EINPROGRESS) {
		debug(LOG_ERR, "Failed to connect to Unix socket %s: %s", unix_path, strerror(errno));
		close(fd);
		return NULL;
	}

	/* Create bufferevent */
	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		debug(LOG_ERR, "Failed to create bufferevent for Unix socket");
		close(fd);
		return NULL;
	}

	/* For non-blocking connect, the BEV_EVENT_CONNECTED callback will fire */
	if (ret == 0) {
		/* Connected immediately */
		debug(LOG_DEBUG, "Connected to Unix socket: %s", unix_path);
	} else {
		/* EINPROGRESS — will connect asynchronously */
		debug(LOG_DEBUG, "Connecting to Unix socket: %s", unix_path);
	}

	return bev;
}

/**
 * @brief Sets up a local connection for the proxy client
 */
static int setup_local_connection(struct proxy_client *client) 
{
	struct proxy_service *ps = client->ps;
	
	if (is_udp_proxy(ps)) {
		client->local_proxy_bev = connect_udp_server(client->base);
	} else if (is_uds_proxy(ps)) {
		client->local_proxy_bev = connect_unix_server(client->base, ps->plugin_unix_path);
	} else if (!is_socks5_proxy(ps) && !has_service_type(ps)) {
		client->local_proxy_bev = connect_server(client->base, ps->local_ip, ps->local_port);
	} else {
		debug(LOG_INFO, "socks5 proxy client or xdpi proxy client: connection deferred ...");
		return 0;
	}

	if (!client->local_proxy_bev) {
		debug(LOG_ERR, "frpc tunnel connect local proxy port [%d] failed!", ps->local_port);
		del_proxy_client_by_stream_id(client->stream_id);
		return -1;
	}

	return 1;
}

/**
 * Initiates and establishes a xfrp tunnel for the specified proxy client.
 */
void start_xfrp_tunnel(struct proxy_client *client)
{
	if (!client || !client->ctl_bev || !client->base || !client->ps ||
		    (!client->ps->local_port && !is_uds_proxy(client->ps))) {
		debug(LOG_ERR, "Invalid client configuration");
		return;
	}

	if (setup_local_connection(client) <= 0) {
		return;
	}

	struct common_conf *c_conf = get_common_config();
	struct proxy_service *ps = client->ps;

	debug(LOG_DEBUG, "proxy server [%s:%d] <---> client [%s:%d]", 
		  c_conf->server_addr, ps->remote_port,
		  ps->local_ip ? ps->local_ip : "127.0.0.1", ps->local_port);

	bufferevent_data_cb proxy_s2c_recv, proxy_c2s_recv;
	setup_proxy_callbacks(client, &proxy_c2s_recv, &proxy_s2c_recv);

	if (!c_conf->tcp_mux) {
		bufferevent_setcb(client->ctl_bev, proxy_s2c_recv, NULL, 
						 xfrp_worker_event_cb, client);
		bufferevent_enable(client->ctl_bev, EV_READ|EV_WRITE);
	}

	bufferevent_setwatermark(client->local_proxy_bev, EV_READ, 0, 0);

	bufferevent_setcb(client->local_proxy_bev, proxy_c2s_recv, NULL,
					 xfrp_proxy_event_cb, client);
	bufferevent_enable(client->local_proxy_bev, EV_READ|EV_WRITE);
}

/**
 * @brief Sends any remaining data in the client's data tail buffer
 */
int send_client_data_tail(struct proxy_client *client)
{
	if (!client) {
		debug(LOG_ERR, "Invalid proxy client pointer");
		return -1;
	}

	if (!client->data_tail || client->data_tail_size == 0) {
		debug(LOG_DEBUG, "No data tail to send");
		return 0;
	}

	if (!client->local_proxy_bev) {
		debug(LOG_ERR, "Invalid local proxy bufferevent");
		return -1;
	}

	int bytes_written = bufferevent_write(client->local_proxy_bev,
										client->data_tail,
										client->data_tail_size);

	free(client->data_tail);
	client->data_tail = NULL;
	client->data_tail_size = 0;

	return bytes_written;
}

/**
 * @brief Frees resources associated with a proxy client
 */
static void 
free_proxy_client(struct proxy_client *client)
{
	if (!client) {
		debug(LOG_DEBUG, "Attempted to free NULL proxy client");
		return;
	}

	debug(LOG_DEBUG, "Freeing proxy client with stream ID: %d", client->stream_id);

	if (client->local_proxy_bev) {
		bufferevent_free(client->local_proxy_bev);
		client->local_proxy_bev = NULL;
	}

	/* Free data tail */
	if (client->data_tail) {
		free(client->data_tail);
		client->data_tail = NULL;
		client->data_tail_size = 0;
	}

	/* Free per-client parser buffers */
	if (client->socks5_buf) {
		free(client->socks5_buf);
		client->socks5_buf = NULL;
	}
	if (client->xdpi_buf) {
		free(client->xdpi_buf);
		client->xdpi_buf = NULL;
	}

	tmux_stream_release(&client->stream);

	free(client);
}

/**
 * @brief Removes a proxy client from the global hash table and frees its resources
 */
static int
del_proxy_client(struct proxy_client *client)
{
	if (!client) {
		debug(LOG_INFO, "Cannot delete NULL proxy client");
		return -1;
	}
	
	if (!all_pc) {
		debug(LOG_INFO, "Global proxy client table is NULL");
		return -1;
	}

	debug(LOG_DEBUG, "Deleting proxy client with stream ID: %d", client->stream_id);
	
	HASH_DEL(all_pc, client);
	free_proxy_client(client);
	
	return 0;
}

/**
 * @brief Deletes a proxy client and its associated stream based on the stream ID
 */
void del_proxy_client_by_stream_id(uint32_t sid) {
	if (sid == 0) {
		debug(LOG_DEBUG, "Invalid stream ID: 0");
		return;
	}

	del_stream(sid);

	struct proxy_client *pc = get_proxy_client(sid);
	if (pc) {
		del_proxy_client(pc);
	} else {
		debug(LOG_DEBUG, "No proxy client found to delete for stream ID: %d", sid);
	}
}

/**
 * @brief Retrieves a proxy client by its stream ID
 */
struct proxy_client *get_proxy_client(uint32_t sid)
{
	struct proxy_client *pc = NULL;
	
	if (sid == 0) {
		debug(LOG_DEBUG, "Invalid stream ID: 0");
		return NULL;
	}
	
	HASH_FIND_INT(all_pc, &sid, pc);
	
	if (!pc) {
		debug(LOG_DEBUG, "No proxy client found for stream ID: %d", sid);
	}
	
	return pc;
}

/**
 * @brief Creates and initializes a new proxy client
 */
struct proxy_client *new_proxy_client() 
{
	struct proxy_client *client = NULL;
	
	client = calloc(1, sizeof(struct proxy_client));
	if (!client) {
		debug(LOG_ERR, "Failed to allocate memory for proxy client");
		return NULL;
	}

	client->stream_id = get_next_session_id();
	
	init_tmux_stream(&client->stream, client->stream_id, INIT);

	HASH_ADD_INT(all_pc, stream_id, client);
	debug(LOG_DEBUG, "Created new proxy client with stream ID: %d", client->stream_id);
	
	return client;
}


/**
 * @brief Clears and releases all proxy client resources
 */
void clear_all_proxy_client()
{
	clear_stream();

	if (!all_pc) {
		debug(LOG_DEBUG, "No proxy clients to clear");
		return;
	}

	struct proxy_client *current = NULL;
	struct proxy_client *temp = NULL;

	HASH_ITER(hh, all_pc, current, temp) {
		if (current) {
			HASH_DEL(all_pc, current);
			free_proxy_client(current);
		}
	}

	all_pc = NULL;

	debug(LOG_DEBUG, "All proxy clients cleared successfully");
}

int xdpi_engine(struct proxy_client *client, const unsigned char *data, size_t len)
{
	if (!client || !data || len == 0) {
		return -1;
	}

	struct proxy_service *ps = client->ps;
	if (!ps) {
		return -1;
	}

	if (client->xdpi_state == XDPI_BLOCKED) {
		return -1;
	}

	if (client->xdpi_state == XDPI_VERIFIED) {
		return 0;
	}

	switch (ps->service_type) {
		case SERVICE_SSH:
			if (len >= 20 && data[0] == 'S' && data[1] == 'S' && data[2] == 'H') {
				const char *known_clients[] = {
					"OpenSSH", "PuTTY", "WinSCP", "FileZilla", "SecureCRT",
					"Xshell", "Bitvise", "SSH Tectia", "Tera Term", "KiTTY",
					"Royal TSX", "Termius", "Tabby", "Cyberduck", "ForkLift",
					"Transmit", "CoreFTP", "SmartFTP", "FlashFXP", "FTP Rush",
					NULL
				};

				for (int i = 0; known_clients[i] != NULL; i++) {
					if (strstr((const char *)data, known_clients[i]) != NULL) {
						client->xdpi_state = XDPI_VERIFIED;
						debug(LOG_INFO, "XDPI engine detected valid SSH client: %s", known_clients[i]);
						return 0;
					}
				}

				debug(LOG_WARNING, "XDPI engine detected unknown SSH client, blocking connection");
				debug(LOG_WARNING, "data: %s", data);
				client->xdpi_state = XDPI_BLOCKED;
				return -1;
			}
			break;

		case SERVICE_HTTP:
			if (len >= 4 && 
				((data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') ||
				 (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') ||
				 (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') ||
				 (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' '))) {
				client->xdpi_state = XDPI_VERIFIED;
				return 0;
			}
			break;

		case SERVICE_HTTPS:
			if (len >= 3 && data[0] == 0x16 && data[1] == 0x03) {
				client->xdpi_state = XDPI_VERIFIED;
				return 0;
			}
			break;
		case SERVICE_MSTSC:
			if (len == 47 && data[0] == 0x03 && data[1] == 0x00 && data[2] == 0x00 && data[5] == 0xe0) {
				if (memcmp((const char *)&data[11], "Cookie:", 7) == 0 && data[43] == 0x0b) {
					client->xdpi_state = XDPI_VERIFIED;
					debug(LOG_INFO, "XDPI engine verified the RDP protocol, len: %zu", len);
					return 0;
				} 
			} 

			debug(LOG_WARNING, "XDPI engine detected unknown RDP client, len: %zu", len);
			break;
		case SERVICE_RDP:
			if (len >= 19 && data[0] == 0x03 && data[1] == 0x00 && data[2] == 0x00) {
				client->xdpi_state = XDPI_VERIFIED;
				return 0;
			}
			break;
		case SERVICE_VNC:
			if (len >= 4 && data[0] == 'R' && data[1] == 'F' && data[2] == 'B' && data[3] == ' ') {
				client->xdpi_state = XDPI_VERIFIED;
				return 0;
			}
			break;

		case SERVICE_TELNET:
			if (len >= 3 && data[0] == 0xFF && data[1] == 0xFB) {
				client->xdpi_state = XDPI_VERIFIED;
				return 0;
			}
			break;

		case NO_XDPI:
			client->xdpi_state = XDPI_VERIFIED;
			return 0;

		default:
			break;
	}

	client->xdpi_state = XDPI_BLOCKED;
	return -1;
}
