
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
 * 
 * @param bev Bufferevent that triggered the callback
 * @param what Type of event that occurred
 * @param ctx Context pointer (unused)
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
 * @param client Proxy client to handle
 * @return int 0 on success, -1 on failure
 */
static int handle_post_connection_data(struct proxy_client *client) {
	if (!client) return -1;

	if (!is_iod_proxy(client->ps) && client->data_tail_size > 0) {
		debug(LOG_DEBUG, "Sending pending client data");
		return send_client_data_tail(client);
	} else if (is_iod_proxy(client->ps)) {
		assert(client->data_tail_size != 0);
		debug(LOG_INFO, "Sending IOD data: data_tail_size is %d", client->data_tail_size);
		uint32_t written = tmux_stream_write(client->ctl_bev, client->data_tail, client->data_tail_size, &client->stream);
		if (written < client->data_tail_size) {
			debug(LOG_NOTICE, "Stream %d: Partial write %u/%zu bytes", client->stream.id, written, client->data_tail_size);
		}
		free(client->data_tail);
		client->data_tail = NULL;
		client->data_tail_size = 0;
		client->iod_state = 1;
		return 0;
	} else if (is_socks5_proxy(client->ps)) {
		struct ring_buffer *rb = &client->stream.rx_ring;
		if (rb->sz > 0) {
			tx_ring_buffer_write(client->local_proxy_bev, rb, rb->sz);
		}
		client->state = SOCKS5_ESTABLISHED;
		return 0;
	}
	return 0;
}

/**
 * @brief Handles proxy client disconnection
 * 
 * @param client Proxy client that disconnected
 * @param bev Bufferevent associated with the connection
 * @param error_msg Error message to log
 */
static void handle_proxy_disconnect(struct proxy_client *client, 
								  struct bufferevent *bev, 
								  const char *error_msg) {
	if (!client || !client->ps) return;

	debug(LOG_INFO, "Proxy close connection %s - stream_id %d: %s",
		  error_msg, client->stream_id, strerror(errno));

	if (tmux_stream_close(client->ctl_bev, &client->stream)) {
		bufferevent_free(bev);
		client->local_proxy_bev = NULL;
	}
}

/**
 * @brief Event callback for proxy connection events
 * 
 * @param bev Bufferevent that triggered the callback
 * @param what Type of event that occurred
 * @param ctx Context pointer (proxy client)
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
		} else if (is_iod_proxy(client->ps)) {
			error_msg = "iod proxy";
		} else {
			error_msg = "server";
		}
		handle_proxy_disconnect(client, bev, error_msg);
	} else if (what & BEV_EVENT_CONNECTED) {
		debug(LOG_DEBUG, "Client %d connected", client->stream_id);
		handle_post_connection_data(client);
	}
}

/**
 * @brief Check if proxy service is of a specific type
 * @param ps Pointer to proxy service structure
 * @param type String representing the proxy type to check
 * @param extra_check Additional condition to verify (pass 1 to ignore)
 * @return 1 if matches, 0 otherwise
 */
static int is_proxy_type(const struct proxy_service *ps, const char *type, int extra_check) {
	if (!ps || !ps->proxy_type) {
		return 0;
	}
	return (strcmp(ps->proxy_type, type) == 0) && extra_check;
}

/**
 * @brief Check if proxy service is FTP type
 * @param ps Pointer to proxy service structure
 * @return 1 if FTP proxy, 0 otherwise
 */
int is_ftp_proxy(const struct proxy_service *ps) {
	return is_proxy_type(ps, "ftp", ps->remote_data_port > 0);
}

/**
 * @brief Check if proxy service is SOCKS5 type
 * @param ps Pointer to proxy service structure
 * @return 1 if SOCKS5 proxy, 0 otherwise
 */
int is_socks5_proxy(const struct proxy_service *ps) {
	return is_proxy_type(ps, "socks5", 1);
}

int is_iod_proxy(const struct proxy_service *ps) {
	return is_proxy_type(ps, "iod", 1);
}

/**
 * @brief Check if proxy service is UDP type
 * @param ps Pointer to proxy service structure
 * @return 1 if UDP proxy, 0 otherwise
 */
int is_udp_proxy(const struct proxy_service *ps) {
	return is_proxy_type(ps, "udp", 1);
}

/**
 * Sets up callback functions for a proxy client
 *
 * @param client Pointer to the proxy client structure for which callbacks will be configured
 * 
 * This function configures various callback functions that will be used by the proxy client
 * for handling different events and operations during the proxy communication process.
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
	} else {
		*proxy_c2s_recv = tcp_proxy_c2s_cb;
		*proxy_s2c_recv = tcp_proxy_s2c_cb;
	}
}

/**
 * @brief Sets up a local connection for the proxy client
 * 
 * This function establishes a local connection for the specified proxy client.
 * It handles the connection setup process including socket creation and configuration.
 *
 * @param client Pointer to the proxy client structure containing connection details
 * @return int Returns 0 on success, negative value on failure
 */
static int setup_local_connection(struct proxy_client *client) 
{
	struct proxy_service *ps = client->ps;
	
	if (is_udp_proxy(ps)) {
		client->local_proxy_bev = connect_udp_server(client->base);
	} else if (!is_socks5_proxy(ps) && !is_iod_proxy(ps)) {
		client->local_proxy_bev = connect_server(client->base, ps->local_ip, ps->local_port);
	} else {
		debug(LOG_INFO, "socks5 proxy client or iod proxy client can't connect to remote server here ...");
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
 * 
 * This function starts a new tunnel connection for the given proxy client,
 * setting up the necessary network resources and connection parameters
 * based on the client's configuration.
 *
 * @param client Pointer to the proxy_client structure containing the client configuration
 *              and connection details
 */
void start_xfrp_tunnel(struct proxy_client *client)
{
	if (!client || !client->ctl_bev || !client->base || !client->ps || !client->ps->local_port) {
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

	bufferevent_setcb(client->local_proxy_bev, proxy_c2s_recv, NULL,
					 xfrp_proxy_event_cb, client);
	bufferevent_enable(client->local_proxy_bev, EV_READ|EV_WRITE);
}

/**
 * @brief Sends any remaining data in the client's data tail buffer
 *
 * @param client Pointer to proxy client containing data to be sent
 * @return int Number of bytes written, -1 on error
 */
int send_client_data_tail(struct proxy_client *client)
{
	// Validate input parameters
	if (!client) {
		debug(LOG_ERR, "Invalid proxy client pointer");
		return -1;
	}

	// Check if there's any data to send
	if (!client->data_tail || client->data_tail_size == 0) {
		debug(LOG_DEBUG, "No data tail to send");
		return 0;
	}

	// Verify bufferevent is available
	if (!client->local_proxy_bev) {
		debug(LOG_ERR, "Invalid local proxy bufferevent");
		return -1;
	}

	// Write data to buffer
	int bytes_written = bufferevent_write(client->local_proxy_bev, 
										client->data_tail, 
										client->data_tail_size);

	// Free the data tail buffer
	free(client->data_tail);
	client->data_tail = NULL;
	client->data_tail_size = 0;

	return bytes_written;
}

/**
 * @brief Frees resources associated with a proxy client
 * 
 * @param client Pointer to proxy client to be freed
 * @note If client is NULL, function returns silently
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

	// Free any data tail if it exists
	if (client->data_tail) {
		free(client->data_tail);
		client->data_tail = NULL;
		client->data_tail_size = 0;
	}

	free(client);
}

/**
 * @brief Removes a proxy client from the global hash table and frees its resources
 * 
 * @param client Pointer to proxy client to be deleted
 * @return 0 on success, -1 on failure
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
 *
 * This function performs cleanup by removing both the stream and its associated
 * proxy client from the system. It first validates the stream ID, then removes
 * the stream, and finally removes the proxy client if one exists.
 *
 * @param sid The stream ID to identify which proxy client and stream to remove
 *
 * @note If sid is 0, the function will return without performing any action
 * @note If no proxy client is found for the given stream ID, only the stream will be removed
 */
void del_proxy_client_by_stream_id(uint32_t sid) {
	if (sid == 0) {
		debug(LOG_DEBUG, "Invalid stream ID: 0");
		return;
	}

	// Delete the stream first
	del_stream(sid);

	// Find and delete the proxy client
	struct proxy_client *pc = get_proxy_client(sid);
	if (pc) {
		del_proxy_client(pc);
	} else {
		debug(LOG_DEBUG, "No proxy client found to delete for stream ID: %d", sid);
	}
}

/**
 * @brief Retrieves a proxy client by its stream ID
 * @param sid Stream ID to search for
 * @return struct proxy_client* Pointer to found proxy client, NULL if not found
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
 * 
 * @return struct proxy_client* Pointer to newly created proxy client, NULL if allocation fails
 */
struct proxy_client *new_proxy_client() 
{
	struct proxy_client *client = NULL;
	
	// Allocate memory for new client
	client = calloc(1, sizeof(struct proxy_client));
	if (!client) {
		debug(LOG_ERR, "Failed to allocate memory for proxy client");
		return NULL;
	}

	// Initialize client fields
	client->stream_id = get_next_session_id();
	
	// Initialize stream
	init_tmux_stream(&client->stream, client->stream_id, INIT);

	// Add to hash table
	HASH_ADD_INT(all_pc, stream_id, client);
	debug(LOG_DEBUG, "Created new proxy client with stream ID: %d", client->stream_id);
	
	return client;
}


/**
 * @brief Clears and releases all proxy client resources
 * 
 * Frees all memory allocated for proxy clients and resets related data structures.
 * This function should be called during cleanup or shutdown to prevent memory leaks.
 */
void clear_all_proxy_client()
{
	// Clear stream state first
	clear_stream();

	// Early return if no proxy clients exist
	if (!all_pc) {
		debug(LOG_DEBUG, "No proxy clients to clear");
		return;
	}

	struct proxy_client *current = NULL;
	struct proxy_client *temp = NULL;

	// Iterate through all proxy clients and free them
	HASH_ITER(hh, all_pc, current, temp) {
		if (current) {
			HASH_DEL(all_pc, current);
			free_proxy_client(current);
		}
	}

	// Ensure the hash table pointer is nulled
	all_pc = NULL;

	debug(LOG_DEBUG, "All proxy clients cleared successfully");
}
