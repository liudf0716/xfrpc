// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>

#include "debug.h"
#include "client.h"
#include "uthash.h"
#include "config.h"
#include "msg.h"
#include "control.h"
#include "crypto.h"
#include "utils.h"
#include "common.h"
#include "login.h"
#include "tcpmux.h"
#include "proxy.h"

static struct control *main_ctl;
static bool xfrpc_status;
static int is_login;
static time_t pong_time;

static void new_work_connection(struct bufferevent *bev, struct tmux_stream *stream);
static void recv_cb(struct bufferevent *bev, void *ctx);
static void clear_main_control(void);
static void start_base_connect(void);
static void keep_control_alive(void);
static void client_start_event_cb(struct bufferevent *bev, short what, void *ctx);

/**
 * Check if xfrpc client is connected to server
 *
 * @return true if connected, false otherwise
 */
static bool is_xfrpc_connected(void)
{
	return xfrpc_status;
}

/**
 * Updates the global connection status flag for xfrpc.
 * 
 * @param is_connected Boolean flag indicating whether xfrpc is connected (true) or disconnected (false)
 * 
 * Sets the global xfrpc_status variable and logs the new connection state at debug level.
 */
static void set_xfrpc_status(bool is_connected)
{
	// Set global connection status flag 
	xfrpc_status = is_connected;
	debug(LOG_DEBUG, "xfrpc connection status set to: %s", is_connected ? "connected" : "disconnected");
}

/**
 * Sets the work status of a proxy client.
 * 
 * @param client The proxy client structure to modify
 * @param is_start_work Non-zero value to start work, zero to stop
 * @return Returns 1 if client is set to work, 0 if client is set to stop or if invalid parameters
 *
 * This function updates the work_started flag of a proxy client. It performs validation
 * to ensure the client and its proxy service exist before modifying the status.
 */
static int set_client_work_start(struct proxy_client *client, int is_start_work)
{
	if (!client || !client->ps) {
		debug(LOG_ERR, "Invalid client or proxy service");
		return 0;
	}

	client->work_started = (is_start_work != 0);
	return client->work_started;
}

/**
 * @brief Handles errors for proxy client connections
 *
 * This function handles errors that occur on the control connection to the server.
 * It performs cleanup by:
 * 1. Verifying and freeing mismatched control bufferevents
 * 2. Logging the connection error details
 * 3. Freeing the bufferevent
 * 4. Removing the proxy client from tracking
 *
 * @param client The proxy client structure containing connection state
 * @param bev The bufferevent that encountered an error
 * @param c_conf Common configuration containing server connection details
 */
static void handle_client_error(struct proxy_client *client, struct bufferevent *bev, 
				   const struct common_conf *c_conf)
{
	// Verify control bufferevent matches
	if (client->ctl_bev != bev) {
		debug(LOG_ERR, "Bufferevent mismatch - freeing existing control bufferevent");
		bufferevent_free(client->ctl_bev);
		client->ctl_bev = NULL;
	}

	debug(LOG_ERR, "Connection error to server [%s:%d]: %s", 
		  c_conf->server_addr, c_conf->server_port, strerror(errno));

	// Cleanup
	bufferevent_free(bev);
	del_proxy_client_by_stream_id(client->stream_id);
}

/**
 * @brief Handles the setup of a newly connected proxy client
 *
 * This function configures the bufferevent callbacks and initializes 
 * the work connection for a newly connected proxy client. It:
 * - Sets up read/write event callbacks for the bufferevent
 * - Initializes a new work connection with the given bufferevent
 * - Enables the proxy service status
 *
 * @param client Pointer to the proxy client structure
 * @param bev Pointer to the bufferevent structure for this connection
 */
static void handle_client_connected(struct proxy_client *client, struct bufferevent *bev)
{
	// Setup callbacks and enable events
	bufferevent_setcb(bev, recv_cb, NULL, client_start_event_cb, client);
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	// Initialize work connection
	new_work_connection(bev, &main_ctl->stream);
	set_xfrpc_status(true);

	debug(LOG_INFO, "Proxy service started successfully");
}

/**
 * @brief Callback function for handling client connection events
 * 
 * This callback is triggered for connection-related events of a bufferevent. It handles:
 * - Connection errors
 * - EOF (End of File) conditions
 * - Successful connections
 * 
 * The function performs validation of input parameters and retrieves common configuration
 * before processing any events. If errors occur, appropriate error handling is performed.
 *
 * @param bev Pointer to the bufferevent structure that triggered the callback
 * @param what Bit mask of events that triggered the callback (BEV_EVENT_*)
 * @param ctx Context pointer containing the proxy client structure
 * 
 * @note The context (ctx) is expected to be a pointer to proxy_client structure
 */
static void client_start_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	// Validate input parameters
	if (!bev || !ctx) {
		debug(LOG_ERR, "Invalid parameters: bev=%p, ctx=%p", bev, ctx);
		return;
	}

	struct proxy_client *client = (struct proxy_client *)ctx;
	struct common_conf *c_conf = get_common_config();
	if (!c_conf) {
		debug(LOG_ERR, "Failed to get common config");
		return;
	}

	// Handle connection errors and EOF
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		handle_client_error(client, bev, c_conf);
		return;
	}

	// Handle successful connection
	if (what & BEV_EVENT_CONNECTED) {
		handle_client_connected(client, bev);
	}
}

/**
 * @brief Initializes a TCP multiplexing client connection
 *
 * This function sets up a new TCP multiplexing client by:
 * 1. Validating the client and control buffer event
 * 2. Sending initial window update
 * 3. Creating a new work connection
 *
 * @param client Pointer to the proxy client structure containing connection details
 * @return 0 on success, -1 on failure
 *
 * @note Client must have valid proxy_client structure with initialized ctl_bev
 */
static int init_tcp_mux_client(struct proxy_client *client) {
	if (!client || !client->ctl_bev) {
		debug(LOG_ERR, "Invalid client for TCP mux initialization");
		return -1;
	}

	debug(LOG_DEBUG, "New client through TCP mux: stream_id=%d", client->stream_id);
	send_window_update(client->ctl_bev, &client->stream, 0);
	new_work_connection(client->ctl_bev, &client->stream);
	return 0;
}

/**
 * @brief Initializes a direct client connection to a server
 * 
 * This function establishes a direct connection to a specified server using the
 * provided address and port. It creates a bufferevent for the connection and
 * sets up the necessary callbacks.
 *
 * @param client Pointer to the proxy client structure
 * @param server_addr Server address to connect to
 * @param server_port Server port to connect to
 *
 * @return 0 on success, -1 on failure
 *
 * @note The function will log debug messages for both successful and failed
 * connection attempts
 */
static int init_direct_client(struct proxy_client *client, 
							const char *server_addr, 
							int server_port) {
	struct bufferevent *bev = connect_server(client->base, server_addr, server_port);
	if (!bev) {
		debug(LOG_ERR, "Failed to connect to server [%s:%d]", 
			  server_addr, server_port);
		return -1;
	}

	debug(LOG_INFO, "Work connection: connecting to server [%s:%d]...", 
		  server_addr, server_port);

	client->ctl_bev = bev;
	bufferevent_enable(bev, EV_WRITE);
	bufferevent_setcb(bev, NULL, NULL, client_start_event_cb, client);
	
	return 0;
}

/**
 * @brief Creates and initializes a new proxy client connection
 * 
 * This function handles the creation of a new proxy client and establishes
 * its connection. It performs the following steps:
 * 1. Creates a new proxy client instance
 * 2. Retrieves and validates common configuration
 * 3. Initializes the client's event base
 * 4. Sets up the connection based on TCP multiplexing configuration:
 *    - If TCP mux is enabled, initializes multiplexed client
 *    - If TCP mux is disabled, initializes direct client connection
 * 
 * The function includes proper error handling and cleanup for failed operations.
 * 
 * @note This function assumes the existence of a global main_ctl structure
 * @note Memory is properly freed in case of initialization failures
 */
static void new_client_connect()
{
	// Create new proxy client
	struct proxy_client *client = new_proxy_client();
	if (!client) {
		debug(LOG_ERR, "Failed to create new proxy client");
		return;
	}

	// Get and validate common config
	struct common_conf *c_conf = get_common_config();
	if (!c_conf) {
		debug(LOG_ERR, "Failed to get common config");
		free(client);
		return;
	}

	// Initialize client base
	client->base = main_ctl->connect_base;
	if (!client->base) {
		debug(LOG_ERR, "Invalid event base");
		free(client);
		return;
	}

	// Handle connection based on mux configuration
	if (c_conf->tcp_mux) {
		client->ctl_bev = main_ctl->connect_bev;
		if (init_tcp_mux_client(client) != 0) {
			free(client);
			return;
		}
	} else {
		if (init_direct_client(client, c_conf->server_addr, c_conf->server_port) != 0) {
			free(client);
			return;
		}
	}
}

/**
 * @brief Initializes and starts all configured proxy services
 *
 * This function retrieves all configured proxy services and initiates them by:
 * 1. Getting the list of all configured proxy services
 * 2. Iterating through each service
 * 3. Validating each service
 * 4. Skipping MSTSC type proxies
 * 5. Sending new proxy requests for valid services
 *
 * If no proxy services are configured, the function logs a message and returns.
 * Invalid proxy services encountered during iteration are logged and skipped.
 *
 * @note MSTSC proxy types are explicitly skipped during processing
 */
static void start_proxy_services() 
{
	// Get configured proxy services
	struct proxy_service *all_ps = get_all_proxy_services();
	if (!all_ps) {
		debug(LOG_INFO, "No proxy services configured");
		return;
	}

	debug(LOG_INFO, "Starting xfrp proxy services...");

	// Iterate through all proxy services
	struct proxy_service *ps = NULL, *tmp = NULL;
	HASH_ITER(hh, all_ps, ps, tmp) {
		// Validate proxy service
		if (!ps) {
			debug(LOG_ERR, "Invalid proxy service encountered");
			continue;
		}

		// Skip MSTSC proxy type
		if (ps->proxy_type && strcmp(ps->proxy_type, "mstsc") == 0) {
			debug(LOG_DEBUG, "Skipping MSTSC service");
			continue;
		}

		// Send new proxy request
		debug(LOG_DEBUG, "Sending proxy service: %s", ps->proxy_name);
		send_new_proxy(ps);
	}
}

/**
 * @brief Sends a ping message to the FRP server to maintain connection
 *
 * This function validates the bufferevent connection and sends an empty JSON
 * ping message to the FRP server. The ping message helps keep the connection
 * alive and verify connectivity.
 *
 * The message is encrypted before sending using the stream encryption context
 * stored in main_ctl.
 *
 * @note Requires valid main_ctl and connect_bev to be initialized
 */
static void ping(void)
{
	// Validate bufferevent
	if (!main_ctl || !main_ctl->connect_bev) {
		debug(LOG_ERR, "Invalid bufferevent for ping"); 
		return;
	}

	// Send empty ping message
	const char *ping_msg = "{}";
	send_enc_msg_frp_server(main_ctl->connect_bev, 
						   TypePing, 
						   ping_msg, 
						   strlen(ping_msg), 
						   &main_ctl->stream);

	debug(LOG_DEBUG, "Sent ping message");
}

/**
 * @brief Creates and sends a new work connection request to the FRP server
 *
 * This function handles the creation of a new work connection by:
 * 1. Creating a new work connection structure
 * 2. Retrieving the run ID
 * 3. Marshalling the work connection request
 * 4. Sending the request to the FRP server
 *
 * @param bev The bufferevent structure for connection to the FRP server
 * @param stream The tmux stream structure containing stream information
 *
 * @note This function performs cleanup of allocated resources before returning
 * @note The run ID must be initialized during login before calling this function
 *
 * Error conditions:
 * - Invalid bufferevent parameter
 * - Failed work connection creation
 * - Missing run ID
 * - Failed message marshalling
 */
static void new_work_connection(struct bufferevent *bev, struct tmux_stream *stream)
{
	// Validate input parameters
	if (!bev) {
		debug(LOG_ERR, "Invalid bufferevent parameter");
		return;
	}

	// Create new work connection
	struct work_conn *work_c = new_work_conn();
	if (!work_c) {
		debug(LOG_ERR, "Failed to create new work connection");
		return;
	}

	// Get and validate run ID
	work_c->run_id = get_run_id();
	if (!work_c->run_id) {
		debug(LOG_ERR, "Run ID not found - must be initialized during login");
		SAFE_FREE(work_c);
		return;
	}

	// Marshal work connection request
	char *work_conn_msg = NULL;
	int msg_len = new_work_conn_marshal(work_c, &work_conn_msg);
	if (msg_len <= 0 || !work_conn_msg) {
		debug(LOG_ERR, "Failed to marshal work connection request");
		SAFE_FREE(work_c);
		return;
	}

	// Send work connection request
	debug(LOG_DEBUG, "Sending new work connection request: length=%d", msg_len);
	send_msg_frp_server(bev, TypeNewWorkConn, work_conn_msg, msg_len, stream);

	// Cleanup
	SAFE_FREE(work_conn_msg);
	SAFE_FREE(work_c);
}

/**
 * Establishes a connection to a server using libevent bufferevent
 *
 * This function creates a bufferevent socket and connects it to a server specified
 * by name and port. It handles both direct IP connections and hostname-based
 * connections requiring DNS resolution.
 *
 * @param base      The event_base to be used for the connection
 * @param name      The server address (IP or hostname)
 * @param port      The port number to connect to
 *
 * @return         A pointer to the connected bufferevent structure on success,
 *                NULL on failure
 *
 * The function will:
 * - Validate input parameters
 * - Create a new bufferevent socket
 * - For IP addresses: Connect directly using the IP
 * - For hostnames: Use DNS resolution if available
 *
 * @note Requires main_ctl->dnsbase to be initialized for hostname resolution
 * @note The returned bufferevent must be freed by the caller when no longer needed
 */
struct bufferevent *connect_server(struct event_base *base, const char *name, const int port) 
{
	// Validate input parameters
	if (!base || !name || port <= 0) {
		debug(LOG_ERR, "Invalid connection parameters: base=%p, name=%s, port=%d",
			  base, name ? name : "NULL", port);
		return NULL;
	}

	// Create new bufferevent socket
	struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		debug(LOG_ERR, "Failed to create new bufferevent socket");
		return NULL;
	}

	// For IP addresses, connect directly without DNS
	if (is_valid_ip_address(name)) {
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr(name);
		sin.sin_port = htons(port);

		if (bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
			debug(LOG_ERR, "Direct IP connection failed to %s:%d", name, port);
			bufferevent_free(bev);
			return NULL;
		}
	}
	// Otherwise use DNS resolution
	else if (main_ctl && main_ctl->dnsbase) {
		if (bufferevent_socket_connect_hostname(bev, main_ctl->dnsbase, 
											  AF_INET, name, port) < 0) {
			debug(LOG_ERR, "DNS hostname connection failed to %s:%d", name, port);
			bufferevent_free(bev);
			return NULL;
		}
	}
	else {
		debug(LOG_ERR, "No DNS base available for hostname resolution");
		bufferevent_free(bev);
		return NULL;
	}

	return bev;
}

/**
 * @brief Creates and initializes a UDP server connection using libevent
 *
 * This function sets up a UDP socket and creates a bufferevent for it with the following steps:
 * 1. Creates a UDP socket
 * 2. Makes the socket non-blocking
 * 3. Creates a bufferevent for the socket with close-on-free option
 *
 * @param base Pointer to the event_base to be used for the bufferevent
 * @return struct bufferevent* Pointer to the created bufferevent on success, NULL on failure
 *
 * @note The returned bufferevent must be freed by the caller when no longer needed
 * @note The socket will be automatically closed when the bufferevent is freed
 */
struct bufferevent *connect_udp_server(struct event_base *base)
{
	// Validate input parameter
	if (!base) {
		debug(LOG_ERR, "Invalid event base parameter");
		return NULL;
	}

	// Create UDP socket
	evutil_socket_t fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		debug(LOG_ERR, "Failed to create UDP socket: %s", strerror(errno));
		return NULL;
	}

	// Make socket non-blocking
	if (evutil_make_socket_nonblocking(fd) < 0) {
		debug(LOG_ERR, "Failed to make UDP socket non-blocking: %s", strerror(errno));
		evutil_closesocket(fd);
		return NULL;
	}

	// Create bufferevent for UDP socket
	struct bufferevent *bev = bufferevent_socket_new(base, fd, 
													BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		debug(LOG_ERR, "Failed to create UDP bufferevent: %s", strerror(errno));
		evutil_closesocket(fd);
		return NULL;
	}

	debug(LOG_DEBUG, "UDP server connection initialized successfully");
	return bev;
}

/**
 * @brief Schedules a heartbeat timer event
 *
 * This function schedules a periodic heartbeat timer using the heartbeat interval
 * specified in the common configuration. The timer is used to send periodic
 * heartbeat messages to maintain the connection.
 *
 * @param timeout Pointer to the event structure to be scheduled
 * 
 * @note The heartbeat interval is read from the common configuration
 * @note The function will log errors if the timer or config is invalid
 * @note The timer is scheduled with microseconds set to 0
 */
static void schedule_heartbeat_timer(struct event *timeout) {
	if (!timeout) {
		debug(LOG_ERR, "Invalid timer event");
		return;
	}

	struct common_conf *conf = get_common_config();
	if (!conf) {
		debug(LOG_ERR, "Failed to get common config");
		return;
	}

	struct timeval tv = {
		.tv_sec = conf->heartbeat_interval,
		.tv_usec = 0
	};

	if (event_add(timeout, &tv) < 0) {
		debug(LOG_ERR, "Failed to schedule heartbeat timer");
	}
}

/**
 * Checks if the server connection has timed out based on the last pong response time.
 * If a timeout is detected, it resets the session and restarts the control process.
 *
 * The function compares the time elapsed since the last pong response against the
 * heartbeat timeout value from the common configuration. If the elapsed time exceeds
 * the timeout threshold, it triggers a reconnection sequence.
 *
 * @param current_time The current system time to check against
 * 
 * @note Requires pong_time to be set by the pong handler
 * @note Requires valid common configuration with heartbeat_timeout value
 */
static void check_server_timeout(time_t current_time) {
	struct common_conf *conf = get_common_config();
	if (!conf) {
		debug(LOG_ERR, "Failed to get common config");
		return;
	}

	if (!pong_time) {
		return;
	}

	int elapsed = current_time - pong_time;
	if (elapsed > conf->heartbeat_timeout) {
		debug(LOG_INFO, "Server timeout detected: elapsed=%d seconds, timeout=%d seconds", 
			  elapsed, conf->heartbeat_timeout);

		reset_session_id();
		clear_main_control();
		run_control();
	}
}

/**
 * @brief Timer callback handler for heartbeat operations
 *
 * This function handles periodic heartbeat operations:
 * 1. Sends ping to server if client is connected
 * 2. Reschedules the next heartbeat timer
 * 3. Checks for server timeout condition
 *
 * @param fd Socket file descriptor (unused)
 * @param event Event type that triggered callback (unused) 
 * @param arg User-provided callback argument (unused)
 *
 * @note The function uses global state to track connection status and timing
 * @note If getting current time fails, the function returns early without timeout check
 */
static void heartbeat_handler(evutil_socket_t fd, short event, void *arg) {
	// Send ping if client is connected
	if (is_xfrpc_connected()) {
		debug(LOG_INFO, "Sending heartbeat ping to server");
		ping();
	}

	// Reschedule next heartbeat
	schedule_heartbeat_timer(main_ctl->ticker_ping);

	// Check for server timeout
	time_t current_time = time(NULL);
	if (current_time == (time_t)-1) {
		debug(LOG_ERR, "Failed to get current time");
		return;
	}

	check_server_timeout(current_time);
}

/**
 * Handles configuration for FTP proxy service by updating the remote data port
 * of the main FTP proxy service.
 *
 * @param ps The proxy service containing FTP configuration
 * @param npr The new proxy response containing remote port information
 *
 * @return 1 on successful configuration, 0 if main service not found or invalid port
 *
 * This function:
 * 1. Looks up the main FTP proxy service using the configuration proxy name
 * 2. Validates the remote port from the new proxy response
 * 3. Updates the main service's remote data port if validation succeeds
 */
static int handle_ftp_configuration(struct proxy_service *ps, struct new_proxy_response *npr) 
{
	struct proxy_service *main_ps = get_proxy_service(ps->ftp_cfg_proxy_name);
	if (!main_ps) {
		debug(LOG_ERR, "Main FTP proxy service '%s' not found", ps->ftp_cfg_proxy_name);
		return 0;
	}

	debug(LOG_DEBUG, "Found main FTP proxy service '%s'", main_ps->proxy_name);

	if (npr->remote_port <= 0) {
		debug(LOG_ERR, "Invalid FTP remote data port: %d", npr->remote_port);
		return 0;
	}

	main_ps->remote_data_port = npr->remote_port;
	return 1;
}

/**
 * @brief Processes the raw response for a proxy service
 *
 * @param npr Pointer to the new proxy response structure
 * @return int Returns status code:
 *             0 on success
 *             negative value on failure
 */
static int proxy_service_resp_raw(struct new_proxy_response *npr)
{
	// Validate input parameter
	if (!npr) {
		debug(LOG_ERR, "Invalid new proxy response parameter");
		return 1;
	}

	// Check for error response
	if (npr->error && strlen(npr->error) > 2) {
		debug(LOG_ERR, "New proxy response error: %s", npr->error);
		return 1;
	}
	
	// Validate proxy name
	if (!npr->proxy_name || strlen(npr->proxy_name) == 0) {
		debug(LOG_ERR, "Invalid or empty proxy name in response");
		return 1;
	}

	// Get proxy service
	struct proxy_service *ps = get_proxy_service(npr->proxy_name);
	if (!ps) {
		debug(LOG_ERR, "Proxy service '%s' not found", npr->proxy_name);
		return 1;
	}

	if (!ps->proxy_type) {
		debug(LOG_ERR, "Proxy type is NULL for service '%s'", npr->proxy_name);
		return 1;
	}

	// Handle FTP configuration if present
	if (ps->ftp_cfg_proxy_name) {
		if (!handle_ftp_configuration(ps, npr)) {
			return 1;
		}
	}

	return 0;
}

/**
 * @brief Handles encrypted message and decrypts it
 *
 * @param enc_msg Pointer to the encrypted message buffer
 * @param ilen Length of the input encrypted message
 * @param out Double pointer to store the decrypted output message
 *
 * @return int Returns status code indicating success or failure of decryption
 */
static int handle_enc_msg(const uint8_t *enc_msg, int ilen, uint8_t **out)
{
	// Validate input parameters
	if (!enc_msg || !out || ilen <= 0) {
		debug(LOG_ERR, "Invalid input parameters: msg=%p, out=%p, length=%d", 
			  enc_msg, out, ilen);
		return -1;
	}

	// Initialize decoder if needed
	const uint8_t *buf = enc_msg;
	int remaining_len = ilen;

	if (!is_decoder_inited()) {
		int block_size = get_block_size();
		if (remaining_len < block_size) {
			debug(LOG_ERR, "Insufficient data for decoder initialization: need %d, got %d",
				  block_size, remaining_len);
			return -1;
		}

		if (!init_main_decoder(buf)) {
			debug(LOG_ERR, "Failed to initialize decoder");
			return -1;
		}

		buf += block_size;
		remaining_len -= block_size;

		// Check if we only received initialization vector
		if (remaining_len == 0) {
			debug(LOG_DEBUG, "Received only initialization vector data");
			*out = NULL;
			return 0;
		}
	}

	// Decrypt the message
	uint8_t *dec_msg = NULL;
	size_t dec_len = decrypt_data(buf, remaining_len, get_main_decoder(), &dec_msg);
	
	if (dec_len <= 0 || !dec_msg) {
		debug(LOG_ERR, "Decryption failed");
		return -1;
	}

	*out = dec_msg;
	return dec_len;
}

/**
 * @brief Handles the request for a work connection type
 * 
 * This function processes requests related to work connection types in the xfrpc
 * system. It is intended to be used as a callback for handling specific connection
 * type requests.
 * 
 * @param ctx Pointer to the context data for the work connection request
 * 
 * @note This function is static and only accessible within the current compilation unit
 */
static void handle_type_req_work_conn(void *ctx)
{
	if (!is_xfrpc_connected()) {
		start_proxy_services();
		set_xfrpc_status(true);
	}
	new_client_connect();
}

/**
 * @brief Handles the response message for a new proxy setup
 *
 * This function processes the response received after requesting a new proxy setup.
 * It interprets the message header containing proxy setup response information.
 *
 * @param msg Pointer to the message header structure containing response data
 *
 * @note This function is for internal use within the control module
 */
static void handle_type_new_proxy_resp(struct msg_hdr *msg)
{
	struct new_proxy_response *npr = new_proxy_resp_unmarshal((const char *)msg->data);
	if (!npr) {
		debug(LOG_ERR, "Failed to unmarshal new proxy response");
		return;
	}

	proxy_service_resp_raw(npr);
	SAFE_FREE(npr);
}

/**
 * @brief Check if a proxy service is available based on time settings
 * 
 * @param ps The proxy service structure to check
 * @return int Returns 1 if service is available, 0 if not
 */
static int is_service_available(struct proxy_service *ps)
{
    if (!ps) {
        return 0;
    }

    // If both start_hour and end_hour are 0, service is always available
    if (ps->start_time == 0 && ps->end_time == 0) {
        return 1;
    }

    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    int current_hour = tm_now->tm_hour;

    // Handle case where service period crosses midnight
    if (ps->end_time < ps->start_time) {
        return (current_hour >= ps->start_time || current_hour < ps->end_time);
    }

    // Normal case: service period within same day
    return (current_hour >= ps->start_time && current_hour < ps->end_time);
}

/**
 * @brief Handles the start work connection message type
 *
 * @param msg Pointer to the message header structure
 * @param len Length of the message
 * @param ctx Pointer to context data
 *
 * This function processes messages of type 'start work connection'
 * received from the frp server.
 */
static void handle_type_start_work_conn(struct msg_hdr *msg, int len, void *ctx)
{
    struct start_work_conn_resp *sr = start_work_conn_resp_unmarshal((const char *)msg->data);
    if (!sr) {
        debug(LOG_ERR, "Failed to unmarshal TypeStartWorkConn");
        return;
    }

    struct proxy_service *ps = get_proxy_service(sr->proxy_name);
    if (!ps) {
        debug(LOG_ERR, "Proxy service [%s] not found for TypeStartWorkConn", sr->proxy_name);
        SAFE_FREE(sr);
        return;
    }

    // Check if service is available at current time
    if (!is_service_available(ps)) {
        debug(LOG_INFO, "Proxy service [%s] is not available at current time", sr->proxy_name);
        SAFE_FREE(sr);
        return;
    }

    assert(ctx);
    struct proxy_client *client = (struct proxy_client *)ctx;
    client->ps = ps;

    int remaining_len = len - sizeof(struct msg_hdr) - msg_hton(msg->length);
    debug(LOG_DEBUG, "Proxy service [%s] [%s:%d] starting work connection. Remaining data length %d",
          sr->proxy_name, ps->local_ip, ps->local_port, remaining_len);

    if (remaining_len > 0) {
        client->data_tail_size = remaining_len;
        client->data_tail = msg->data + msg_hton(msg->length);
        debug(LOG_DEBUG, "Data tail is %s", client->data_tail);
    }

    start_xfrp_tunnel(client);
    set_client_work_start(client, 1);
    SAFE_FREE(sr);
}

/**
 * @brief Handles UDP packet types in message processing
 *
 * @param msg Pointer to the message header structure containing packet information
 * @param ctx Pointer to context data needed for packet processing
 *
 * This function processes UDP type packets received in the message header.
 * It performs the necessary handling and routing of UDP packets based on
 * the message contents and context provided.
 */
static void handle_type_udp_packet(struct msg_hdr *msg, void *ctx)
{
	struct udp_packet *udp = udp_packet_unmarshal((const char *)msg->data);
	if (!udp) {
		debug(LOG_ERR, "Failed to unmarshal TypeUDPPacket");
		return;
	}

	debug(LOG_DEBUG, "Received UDP packet from server, content: %s", udp->content);
	assert(ctx);
	struct proxy_client *client = (struct proxy_client *)ctx;
	assert(client->ps);

	handle_udp_packet(udp, client);
	SAFE_FREE(udp);
}

/**
 * @brief Handles the control work based on received buffer data
 *
 * Processes control messages received in the buffer and performs
 * corresponding control operations based on the message content.
 *
 * @param buf Pointer to the received data buffer
 * @param len Length of the received data in bytes
 * @param ctx Context pointer for additional data
 */
static void handle_control_work(const uint8_t *buf, int len, void *ctx)
{
	uint8_t *frps_cmd = NULL;

	if (!ctx) {
		if (handle_enc_msg(buf, len, &frps_cmd) <= 0 || !frps_cmd) {
			return;
		}
	} else {
		frps_cmd = (uint8_t *)buf;
	}

	struct msg_hdr *msg = (struct msg_hdr *)frps_cmd;
	uint8_t cmd_type = msg->type;

	switch (cmd_type) {
	case TypeReqWorkConn:
		handle_type_req_work_conn(ctx);
		break;
	case TypeNewProxyResp:
		handle_type_new_proxy_resp(msg);
		break;
	case TypeStartWorkConn:
		handle_type_start_work_conn(msg, len, ctx);
		break;
	case TypeUDPPacket:
		handle_type_udp_packet(msg, ctx);
		break;
	case TypePong:
		pong_time = time(NULL);
		break;
	default:
		debug(LOG_INFO, "Unsupported command type %d; ctx is %s", cmd_type, ctx ? "not NULL" : "NULL");
		break;
	}

	if (!ctx)
		free(frps_cmd);
}

static int validate_login_msg(const struct msg_hdr *mhdr) {
	if (!mhdr || mhdr->type != TypeLoginResp) {
		debug(LOG_ERR, "Invalid message type: expected %d, got %d", 
			  TypeLoginResp, mhdr ? mhdr->type : -1);
		return 0;
	}
	return 1;
}

/**
 * Processes the login response message from the server
 * 
 * @param mhdr Pointer to the message header structure containing login response
 * @return Returns status code: 0 on success, negative value on failure
 */
static int process_login_response(const struct msg_hdr *mhdr) {
	struct login_resp *lres = login_resp_unmarshal((const char *)mhdr->data);
	if (!lres) {
		debug(LOG_ERR, "Failed to unmarshal login response");
		return 0;
	}

	int success = login_resp_check(lres);
	free(lres);

	if (!success) {
		debug(LOG_ERR, "Login validation failed");
		return 0;
	}

	return 1;
}

/**
 * @brief Handles any remaining data after processing the message header
 * 
 * Processes remaining data from a message after the header has been handled.
 * 
 * @param mhdr Pointer to the message header structure
 * @param login_len Length of the login data
 * @param ilen Input length of the data
 * 
 * @note This function assumes the message header has already been validated
 */
static void handle_remaining_data(struct msg_hdr *mhdr, int login_len, int ilen) {
	struct common_conf *c_conf = get_common_config();
	if (!c_conf || c_conf->tcp_mux) {
		return;
	}

	uint8_t *enc_msg = mhdr->data + login_len;
	uint8_t *frps_cmd = NULL;
	
	int nret = handle_enc_msg(enc_msg, ilen, &frps_cmd);
	if (nret <= 0 || !frps_cmd) {
		debug(LOG_ERR, "Failed to handle encrypted message");
		return;
	}

	if (frps_cmd[0] != TypeReqWorkConn) {
		debug(LOG_ERR, "Unexpected message type: %d", frps_cmd[0]);
		free(frps_cmd);
		return;
	}

	start_proxy_services();
	set_xfrpc_status(true);
	new_client_connect();
	
	free(frps_cmd);
}


/**
 * @brief Handles the response received after a login attempt
 *
 * @param buf Pointer to the buffer containing the login response data
 * @param len Length of the response buffer in bytes
 *
 * @return Returns the result of processing the login response
 *         (specific return values should be documented based on implementation)
 *
 * @note This function processes the server's response to a login request
 *       in the xfrpc protocol
 */
static int handle_login_response(const uint8_t *buf, int len)
{
	if (!buf || len <= 0) {
		debug(LOG_ERR, "Invalid input parameters");
		return 0;
	}

	struct msg_hdr *mhdr = (struct msg_hdr *)buf;
	if (!validate_login_msg(mhdr)) {
		return 0;
	}

	if (!process_login_response(mhdr)) {
		return 0;
	}

	is_login = 1;
	
	int login_len = msg_hton(mhdr->length);
	int remaining_len = len - login_len - sizeof(struct msg_hdr);
	
	debug(LOG_INFO, "Login successful - message length: %d, total length: %d, remaining: %d", 
		  login_len, len, remaining_len);

	if (remaining_len > 0) {
		handle_remaining_data(mhdr, login_len, remaining_len);
	}

	return 1;
}

/**
 * @brief Handles messages received from frps server
 *
 * @param buf Pointer to buffer containing the message
 * @param len Length of the message in bytes
 * @param ctx Context pointer for additional data
 * 
 * @details This function processes incoming messages from the frps (frp server)
 *          and performs appropriate handling based on the message content
 */
static void handle_frps_msg(uint8_t *buf, int len, void *ctx) 
{
	// Validate input parameters
	if (!buf || len <= 0) {
		debug(LOG_ERR, "Invalid message buffer or length");
		return;
	}

	// Handle message based on login state
	if (!is_login) {
		// Handle login response first
		if (!handle_login_response(buf, len)) {
			debug(LOG_ERR, "Login response handling failed");
			return;
		}
	} else {
		// Handle control messages after successful login
		debug(LOG_DEBUG, "Processing control message: length=%d", len);
		handle_control_work(buf, len, ctx);
	}
}

static struct tmux_stream abandon_stream;

/**
 * @brief Handles TCP multiplexing communication
 *
 * This function processes TCP multiplexing data received from the bufferevent.
 *
 * @param bev The bufferevent structure containing the TCP connection
 * @param len Length of the data to be handled
 * @param ctx Context pointer for additional data (can be NULL)
 *
 * @details This function is called when TCP multiplexing data needs to be 
 * processed. It manages the communication between the client and server 
 * in a multiplexed TCP connection.
 */
static void handle_tcp_mux(struct bufferevent *bev, int len, void *ctx)
{
	static struct tcp_mux_header tmux_hdr;
	static uint32_t stream_len = 0;

	while (len > 0) {
		struct tmux_stream *cur = get_cur_stream();
		size_t nr = 0;

		if (!cur) {
			memset(&tmux_hdr, 0, sizeof(tmux_hdr));
			uint8_t *data = (uint8_t *)&tmux_hdr;

			if (len < sizeof(tmux_hdr)) {
				debug(LOG_INFO, "len [%d] < sizeof tmux_hdr", len);
				break;
			}

			nr = bufferevent_read(bev, data, sizeof(tmux_hdr));
			assert(nr == sizeof(tmux_hdr));
			assert(validate_tcp_mux_protocol(&tmux_hdr) > 0);
			len -= nr;

			if (tmux_hdr.type == DATA) {
				uint32_t stream_id = ntohl(tmux_hdr.stream_id);
				stream_len = ntohl(tmux_hdr.length);
				cur = get_stream_by_id(stream_id);
				if (!cur) {
					debug(LOG_INFO, "cur is NULL stream_id is %d, stream_len is %d len is %d",
						  stream_id, stream_len, len);
					if (stream_len > 0)
						cur = &abandon_stream;
					else
						continue;
				}

				if (len == 0) {
					set_cur_stream(cur);
					break;
				}
				if (len >= stream_len) {
					nr = tmux_stream_read(bev, cur, stream_len);
					assert(nr == stream_len);
					len -= stream_len;
				} else {
					nr = tmux_stream_read(bev, cur, len);
					stream_len -= len;
					assert(nr == len);
					set_cur_stream(cur);
					len -= nr;
					break;
				}
			}
		} else {
			assert(tmux_hdr.type == DATA);
			if (len >= stream_len) {
				nr = tmux_stream_read(bev, cur, stream_len);
				assert(nr == stream_len);
				len -= stream_len;
			} else {
				nr = tmux_stream_read(bev, cur, len);
				stream_len -= len;
				assert(nr == len);
				len -= nr;
				break;
			}
		}

		if (cur == &abandon_stream) {
			debug(LOG_INFO, "abandon stream data ...");
			memset(cur, 0, sizeof(abandon_stream));
			set_cur_stream(NULL);
			continue;
		}

		switch (tmux_hdr.type) {
		case DATA:
		case WINDOW_UPDATE:
			handle_tcp_mux_stream(&tmux_hdr, handle_frps_msg);
			break;
		case PING:
			handle_tcp_mux_ping(&tmux_hdr);
			break;
		case GO_AWAY:
			handle_tcp_mux_go_away(&tmux_hdr);
			break;
		default:
			debug(LOG_ERR, "Unexpected tmux_hdr.type");
			exit(-1);
		}

		set_cur_stream(NULL);
	}
}

/**
 * @brief Handles non-multiplexed data received from a buffered event
 *
 * @param bev The bufferevent structure containing the connection
 * @param input The evbuffer containing the received data
 * @param len Length of the data in the input buffer
 * @param ctx Context pointer for additional data (can be NULL)
 * 
 * @details This function processes data received on a non-multiplexed connection.
 *          It is called when data is available to be read from the bufferevent.
 */
static void handle_non_mux(struct bufferevent *bev, struct evbuffer *input, int len, void *ctx)
{
	uint8_t *buf = calloc(len, 1);
	assert(buf);
	evbuffer_remove(input, buf, len);

	handle_frps_msg(buf, len, ctx);
	SAFE_FREE(buf);
}

/**
 * @brief Callback function for handling received data from a bufferevent
 *
 * @param bev The bufferevent structure that received the data
 * @param ctx User-defined context pointer passed to the callback
 *
 * This function is called when data is received on the bufferevent.
 * It processes incoming data and performs necessary handling operations.
 */
static void recv_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	int len = evbuffer_get_length(input);
	if (len <= 0) {
		return;
	}

	struct common_conf *c_conf = get_common_config();

	if (c_conf->tcp_mux) {
		handle_tcp_mux(bev, len, ctx);
	} else {
		handle_non_mux(bev, input, len, ctx);
	}
}

/**
 * @brief Handles connection failures for the xfrpc client
 *
 * This function implements the connection failure handling logic, including
 * retry mechanisms and connection state management.
 *
 * @param c_conf Pointer to the common configuration structure
 * @param retry_times Pointer to the number of retry attempts made
 *
 * @note This function modifies the retry_times parameter to track retry attempts
 */
static void handle_connection_failure(struct common_conf *c_conf, int *retry_times) {
	debug(LOG_ERR, "Connection to server [%s:%d] failed: %s", 
		  c_conf->server_addr, 
		  c_conf->server_port,
		  strerror(errno));

	(*retry_times)++;
	if (*retry_times >= MAX_RETRY_TIMES) {
		debug(LOG_INFO, "Maximum retry attempts (%d) reached", MAX_RETRY_TIMES);
	}

	sleep(RETRY_DELAY_SECONDS);
	
	reset_session_id();
	clear_main_control();
	run_control();
}

/**
 * @brief Handles successful connection events
 *
 * This function processes events when a connection has been successfully established
 *
 * @param bev Pointer to the buffer event structure representing the connection
 * 
 * @note This function is called internally by the event handling system
 */
static void handle_connection_success(struct bufferevent *bev) {
	debug(LOG_INFO, "Successfully connected to xfrp server");
	
	// Initialize window and login
	send_window_update(bev, &main_ctl->stream, 0);
	login();
	
	// Setup keepalive mechanism
	keep_control_alive();
}

/**
 * @brief Callback function for connection events in bufferevent
 *
 * This function handles connection events from a bufferevent socket. It is called
 * when connection state changes occur, such as connect, disconnect, or error conditions.
 *
 * @param bev The bufferevent structure that triggered the event
 * @param what Bitmask of the events that occurred (BEV_EVENT_* flags)
 * @param ctx User-provided context data pointer
 *
 * @note This function is meant to be used as a callback with bufferevent_setcb()
 */
static void connect_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	static int retry_times = 0;
	struct common_conf *c_conf = get_common_config();
	
	if (!c_conf) {
		debug(LOG_ERR, "Failed to get common config");
		return;
	}

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		handle_connection_failure(c_conf, &retry_times);
	} 
	else if (what & BEV_EVENT_CONNECTED) {
		retry_times = 0;
		handle_connection_success(bev);
	}
}

/**
 * Initializes the ping ticker for the control structure.
 * The ping ticker is responsible for managing periodic ping operations
 * to maintain connection health.
 *
 * @param ctl Pointer to the control structure
 * @return 0 on success, negative value on failure
 */
static int init_ping_ticker(struct control *ctl) {
	if (!ctl || !ctl->connect_base) {
		debug(LOG_ERR, "Invalid control structure or event base");
		return -1;
	}

	struct event *ticker = evtimer_new(ctl->connect_base, heartbeat_handler, NULL);
	if (!ticker) {
		debug(LOG_ERR, "Failed to create ping ticker event");
		return -1;
	}

	ctl->ticker_ping = ticker;
	return 0;
}

/**
 * @brief Maintains the control connection to the server alive
 * 
 * This function is responsible for keeping the control connection 
 * to the server active and preventing timeouts. It handles the 
 * periodic sending of heartbeat messages to ensure the connection
 * remains established.
 */
static void keep_control_alive() 
{
	debug(LOG_DEBUG, "Initializing control keepalive");

	// Initialize ping ticker
	if (init_ping_ticker(main_ctl) != 0) {
		debug(LOG_ERR, "Failed to initialize control keepalive");
		return;
	}

	// Set initial pong time
	pong_time = time(NULL);
	if (pong_time == (time_t)-1) {
		debug(LOG_ERR, "Failed to get current time");
		event_free(main_ctl->ticker_ping);
		main_ctl->ticker_ping = NULL;
		return;
	}

	// Start ticker timer
	schedule_heartbeat_timer(main_ctl->ticker_ping);
	debug(LOG_DEBUG, "Control keepalive initialized successfully");
}

/**
 * @brief Initializes a server connection and sets up the bufferevent
 * @param[out] bev_out Double pointer to bufferevent structure to be initialized
 * @return int Returns 0 on success, negative value on failure
 */
static int init_server_connection(struct bufferevent **bev_out, 
								struct event_base *base,
								const char *server_addr, 
								int server_port) 
{
	if (!bev_out || !base || !server_addr) {
		debug(LOG_ERR, "Invalid parameters for server connection");
		return -1;
	}

	// Free existing connection if any
	if (*bev_out) {
		bufferevent_free(*bev_out);
		*bev_out = NULL;
	}

	// Create new connection
	*bev_out = connect_server(base, server_addr, server_port);
	if (!*bev_out) {
		debug(LOG_ERR, "Failed to connect to server [%s:%d]: [%d: %s]",
			  server_addr, server_port, errno, strerror(errno));
		return -1;
	}

	debug(LOG_INFO, "Connecting to server [%s:%d]...", server_addr, server_port);
	return 0;
}

/**
 * @brief Sets up callbacks for the server bufferevent
 *
 * This function configures the event callbacks for a server bufferevent structure.
 * These callbacks handle reading, writing, and error events for the server connection.
 *
 * @param bev Pointer to the bufferevent structure to configure
 * @return Returns 0 on success, -1 on failure
 */
static int setup_server_callbacks(struct bufferevent *bev)
{
	if (!bev) {
		debug(LOG_ERR, "Invalid bufferevent for callback setup");
		return -1;
	}

	bufferevent_enable(bev, EV_WRITE|EV_READ);
	bufferevent_setcb(bev, recv_cb, NULL, connect_event_cb, NULL);
	return 0;
}

/**
 * @brief Initiates the base connection for the xfrpc client
 * 
 * Establishes initial connection setup required for the xfrpc (Fast Reverse Proxy Client)
 * to operate. This function is called during startup phase to create necessary
 * communication channels.
 * 
 * @note This function is static and can only be called from within the control.c file
 */
static void start_base_connect()
{
	struct common_conf *c_conf = get_common_config();
	if (!c_conf) {
		debug(LOG_ERR, "Failed to get common config");
		exit(1);
	}

	// Initialize server connection
	if (init_server_connection(&main_ctl->connect_bev,
							 main_ctl->connect_base,
							 c_conf->server_addr,
							 c_conf->server_port) != 0) {
		exit(1);
	}

	// Setup callbacks for the connection
	if (setup_server_callbacks(main_ctl->connect_bev) != 0) {
		bufferevent_free(main_ctl->connect_bev);
		exit(1);
	}
}

/**
 * Prepares the login message for the frp protocol handshake.
 * 
 * This function constructs a login message that will be sent to the frp server
 * during the initial connection handshake.
 * 
 * @param msg_out Pointer to a char pointer that will store the constructed message
 * @param len_out Pointer to an integer that will store the length of the message
 * 
 * @return Returns 0 on success, negative value on failure
 */
static int prepare_login_message(char **msg_out, int *len_out) {
	if (!msg_out || !len_out) {
		debug(LOG_ERR, "Invalid output parameters");
		return -1;
	}

	int msg_len = login_request_marshal(msg_out);
	if (msg_len <= 0 || !*msg_out) {
		debug(LOG_ERR, "Failed to marshal login request");
		return -1;
	}

	*len_out = msg_len;
	return 0;
}

/**
 * @brief Handles the user login process in xfrpc
 *
 * This function manages the authentication process for users connecting
 * to the xfrp client. It establishes a connection and performs the
 * necessary login handshake with the server.
 *
 * @note This function does not take any parameters and does not return a value
 */
void login(void) {
	char *login_msg = NULL;
	int msg_len = 0;

	// Prepare login message
	if (prepare_login_message(&login_msg, &msg_len) != 0) {
		debug(LOG_ERR, "Failed to prepare login message");
		exit(1);
	}

	// Send login request
	debug(LOG_DEBUG, "Sending login request: length=%d", msg_len);
	send_msg_frp_server(NULL, TypeLogin, login_msg, msg_len, &main_ctl->stream);

	// Cleanup
	SAFE_FREE(login_msg);
}

/**
 * @brief Prepares a message of the specified type for communication
 *
 * @param type The type of message to be prepared
 * @return int Returns 0 on success, negative value on failure
 */
static int prepare_message(const enum msg_type type,
						 const char *msg,
						 const size_t msg_len,
						 struct msg_hdr **msg_out,
						 size_t *total_len)
{
	// Validate inputs
	if (!msg || !msg_out || !total_len) {
		debug(LOG_ERR, "Invalid input parameters");
		return -1;
	}

	// Calculate total message length and allocate memory
	*total_len = msg_len + sizeof(struct msg_hdr);
	struct msg_hdr *req_msg = calloc(*total_len, 1);
	if (!req_msg) {
		debug(LOG_ERR, "Failed to allocate memory for message");
		return -1;
	}

	// Prepare message header and content 
	req_msg->type = type;
	req_msg->length = msg_hton((uint64_t)msg_len);
	memcpy(req_msg->data, msg, msg_len);

	*msg_out = req_msg;
	return 0;
}

/**
 * Sends a message to the FRP server through a buffered event.
 * 
 * @param bev Pointer to the bufferevent structure that represents the connection
 *            to the FRP server for message transmission
 */
void send_msg_frp_server(struct bufferevent *bev,
						const enum msg_type type,
						const char *msg,
						const size_t msg_len,
						struct tmux_stream *stream)
{
	// Get output bufferevent
	struct bufferevent *bout = bev ? bev : main_ctl->connect_bev;
	if (!bout) {
		debug(LOG_ERR, "No valid bufferevent");
		return;
	}

	// Log debug info
	debug(LOG_DEBUG, "Sending message: type=%d, len=%zu", type, msg_len);
	if (msg) {
		debug(LOG_DEBUG, "Message content: %s", msg);
	}

	// Prepare message
	struct msg_hdr *req_msg = NULL;
	size_t total_len = 0;
	if (prepare_message(type, msg, msg_len, &req_msg, &total_len) != 0) {
		return;
	}

	// Send message based on mux configuration
	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		if (tmux_stream_write(bout, (uint8_t *)req_msg, total_len, stream) < 0) {
			debug(LOG_ERR, "Failed to write message through TCP mux");
		}
	} else {
		if (bufferevent_write(bout, (uint8_t *)req_msg, total_len) < 0) {
			debug(LOG_ERR, "Failed to write message directly"); 
		}
	}

	free(req_msg);
}

/**
 * @brief Prepares an encrypted message of specified type
 * 
 * @param type The type of message to be encrypted
 * 
 * @return int Returns 0 on success, negative value on error
 */
static int prepare_encrypted_message(const enum msg_type type,
								   const char *msg,
								   const size_t msg_len,
								   uint8_t **enc_msg_out,
								   size_t *enc_len_out)
{
	// Validate inputs
	if (!msg || !enc_msg_out || !enc_len_out) {
		debug(LOG_ERR, "Invalid input parameters");
		return -1;
	}

	// Prepare message header and content
	size_t total_len = msg_len + sizeof(struct msg_hdr);
	struct msg_hdr *req_msg = calloc(total_len, 1);
	if (!req_msg) {
		debug(LOG_ERR, "Failed to allocate memory for message");
		return -1;
	}

	req_msg->type = type;
	req_msg->length = msg_hton((uint64_t)msg_len);
	memcpy(req_msg->data, msg, msg_len);

	// Encrypt message
	uint8_t *enc_msg = NULL;
	size_t enc_len = encrypt_data((uint8_t *)req_msg, total_len, 
								 get_main_encoder(), &enc_msg);
	free(req_msg);

	if (enc_len <= 0 || !enc_msg) {
		debug(LOG_ERR, "Encryption failed");
		return -1;
	}

	*enc_msg_out = enc_msg;
	*enc_len_out = enc_len;
	return 0;
}

/**
 * @brief Initializes the encoder for stream processing.
 * 
 * This function sets up the encoder for handling data stream encoding
 * within the tmux stream context using a buffered event.
 * 
 * @param bout The buffered event output used for encoding.
 * @param stream Pointer to the tmux stream structure to be initialized.
 * 
 * @return Returns an integer indicating the success (0) or failure (non-zero)
 *         of the encoder initialization.
 */
static int initialize_encoder(struct bufferevent *bout, struct tmux_stream *stream)
{
	struct frp_coder *coder = init_main_encoder();
	if (!coder) {
		debug(LOG_ERR, "Failed to initialize encoder");
		return -1;
	}

	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		if (tmux_stream_write(bout, coder->iv, 16, stream) < 0) {
			debug(LOG_ERR, "Failed to write IV through TCP mux");
			return -1;
		}
	} else {
		if (bufferevent_write(bout, coder->iv, 16) < 0) {
			debug(LOG_ERR, "Failed to write IV directly");
			return -1;
		}
	}
	return 0;
}

/**
 * @brief Sends an encrypted message to the FRP server
 *
 * @param bev Pointer to the bufferevent structure used for network I/O
 *
 * This function handles the encryption and transmission of messages
 * to the FRP (Fast Reverse Proxy) server through the provided bufferevent.
 */
void send_enc_msg_frp_server(struct bufferevent *bev,
							const enum msg_type type,
							const char *msg,
							const size_t msg_len,
							struct tmux_stream *stream)
{
	// Get output bufferevent
	struct bufferevent *bout = bev ? bev : main_ctl->connect_bev;
	if (!bout) {
		debug(LOG_ERR, "No valid bufferevent");
		return;
	}

	// Initialize encoder if needed
	if (!get_main_encoder() && initialize_encoder(bout, stream) != 0) {
		return;
	}

	// Prepare and encrypt message
	uint8_t *enc_msg = NULL;
	size_t enc_len = 0;
	if (prepare_encrypted_message(type, msg, msg_len, &enc_msg, &enc_len) != 0) {
		return;
	}

	// Send encrypted message
	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		if (tmux_stream_write(bout, enc_msg, enc_len, stream) < 0) {
			debug(LOG_ERR, "Failed to write encrypted message through TCP mux");
		}
	} else {
		if (bufferevent_write(bout, enc_msg, enc_len) < 0) {
			debug(LOG_ERR, "Failed to write encrypted message directly");
		}
	}

	free(enc_msg);
}

struct control *
get_main_control() 
{
	return main_ctl;
}

/**
 * Initializes a new FRP connection using libevent.
 *
 * @param bev_out Double pointer to the bufferevent structure that will be initialized
 * @param base Pointer to the event_base structure used for event handling
 *
 * @return Returns an integer indicating success (0) or failure (non-zero)
 */
static int init_frp_connection(struct bufferevent **bev_out, struct event_base *base) {
	struct common_conf *c_conf = get_common_config();
	if (!c_conf) {
		debug(LOG_ERR, "Failed to get common config");
		return -1;
	}

	struct bufferevent *bev = connect_server(base, c_conf->server_addr, c_conf->server_port);
	if (!bev) {
		debug(LOG_ERR, "Failed to connect to server [%s:%d]", 
			  c_conf->server_addr, c_conf->server_port);
		return -1;
	}

	*bev_out = bev;
	return 0;
}

/**
 * @brief Initiates the login process to the FRP server
 *
 * This function starts the process of connecting and logging into the FRP (Fast Reverse Proxy) server.
 * It sets up the necessary event handling in the libevent base for managing the connection.
 *
 * @param base Pointer to the event_base structure that handles event processing
 *
 * @note The event_base must be properly initialized before calling this function
 */
void start_login_frp_server(struct event_base *base) 
{
	struct bufferevent *bev = NULL;
	if (init_frp_connection(&bev, base) != 0) {
		return;
	}

	struct common_conf *c_conf = get_common_config();
	debug(LOG_INFO, "Xfrpc login: connecting to server [%s:%d]...", 
		  c_conf->server_addr, c_conf->server_port);

	bufferevent_enable(bev, EV_WRITE|EV_READ);
	bufferevent_setcb(bev, NULL, NULL, connect_event_cb, NULL);
}

/**
 * @brief Logs an error message related to a proxy
 *
 * @param msg The error message to be logged
 * @param proxy_name The name of the proxy where the error occurred
 */
static void log_proxy_error(const char *msg, const char *proxy_name) {
	debug(LOG_ERR, "%s%s%s", msg, 
		  proxy_name ? ": " : "", 
		  proxy_name ? proxy_name : "");
}

/**
 * Marshals a proxy service structure into a string message format.
 * 
 * @param ps The proxy service structure to be marshaled
 * @param msg_out Pointer to a char pointer where the resulting message will be stored
 * @return Integer value indicating success (0) or failure (non-zero)
 * 
 * This function takes a proxy service structure and converts it into a string format
 * suitable for transmission or storage. The resulting message is dynamically allocated
 * and stored in the location pointed to by msg_out. The caller is responsible for
 * freeing the allocated memory.
 */
static int marshal_proxy_service(struct proxy_service *ps, char **msg_out) {
	if (!ps || !msg_out) {
		log_proxy_error("Invalid proxy service or output buffer", NULL);
		return -1;
	}

	int len = new_proxy_service_marshal(ps, msg_out);
	if (len <= 0 || !*msg_out) {
		log_proxy_error("Failed to marshal proxy service", ps->proxy_name);
		return -1;
	}

	return len;
}

/**
 * @brief Sends a new proxy service configuration to the frpc server
 *
 * @param ps Pointer to the proxy service structure containing configuration details
 *           to be sent to the frpc server
 *
 * This function is responsible for sending newly created or updated proxy service
 * configurations to the frpc server. The proxy service structure contains all
 * necessary parameters and settings for the proxy configuration.
 */
void send_new_proxy(struct proxy_service *ps) {
	if (!ps) {
		log_proxy_error("Invalid proxy service", NULL);
		return;
	}

	char *new_proxy_msg = NULL;
	int msg_len = marshal_proxy_service(ps, &new_proxy_msg);
	if (msg_len < 0) {
		return;
	}

	debug(LOG_DEBUG, "Sending new proxy request: type=%d, name=%s, length=%d", 
		  TypeNewProxy, ps->proxy_name, msg_len);

	send_enc_msg_frp_server(NULL, TypeNewProxy, new_proxy_msg, msg_len, 
						   &main_ctl->stream);

	SAFE_FREE(new_proxy_msg);
}

/**
 * Initializes the event base for the control structure.
 *
 * @param ctl Pointer to control structure to be initialized
 * @return Returns 0 on success, or a negative error code on failure 
 */
static int init_event_base(struct control *ctl)
{
	struct event_base *base = event_base_new();
	if (!base) {
		debug(LOG_ERR, "Failed to create event base");
		return -1;
	}
	ctl->connect_base = base;
	return 0;
}

/**
 * @brief Initializes the DNS base for the control structure
 * 
 * @param ctl Pointer to the control structure
 * @return int Returns 0 on success, -1 on failure
 */
static int init_dns_base(struct control *ctl)
{
	struct evdns_base *dnsbase = evdns_base_new(ctl->connect_base, 1);
	if (!dnsbase) {
		debug(LOG_ERR, "Failed to create DNS base");
		return -1;
	}

	// Configure DNS options
	evdns_base_set_option(dnsbase, "timeout", "1.0");
	evdns_base_set_option(dnsbase, "randomize-case:", "0"); // Disable DNS-0x20 encoding

	// Add DNS servers
	const char *dns_servers[] = {
		"180.76.76.76",    // Baidu DNS
		"223.5.5.5",       // AliDNS
		"223.6.6.6",       // AliDNS
		"114.114.114.114"  // 114DNS
	};

	for (size_t i = 0; i < sizeof(dns_servers)/sizeof(dns_servers[0]); i++) {
		evdns_base_nameserver_ip_add(dnsbase, dns_servers[i]);
	}

	ctl->dnsbase = dnsbase;
	return 0;
}

/**
 * @brief Initializes the main control module of xfrpc
 *
 * This function sets up the primary control structures and resources
 * required for xfrpc operation. It should be called once during
 * program initialization before any other control operations.
 *
 * @return void
 */
void init_main_control()
{
	// Clean up existing control if present
	if (main_ctl && main_ctl->connect_base) {
		event_base_loopbreak(main_ctl->connect_base);
		free(main_ctl);
	}

	// Allocate and initialize new control structure
	main_ctl = calloc(1, sizeof(struct control));
	if (!main_ctl) {
		debug(LOG_ERR, "Failed to allocate main control");
		exit(1);
	}

	// Initialize event base
	if (init_event_base(main_ctl) != 0) {
		free(main_ctl);
		exit(1);
	}

	// Initialize TCP multiplexing if enabled
	struct common_conf *c_conf = get_common_config();
	if (c_conf->tcp_mux) {
		init_tmux_stream(&main_ctl->stream, get_next_session_id(), INIT);
	}

	// Skip DNS initialization if server address is IP
	if (is_valid_ip_address(c_conf->server_addr)) {
		return;
	}

	// Initialize DNS base
	if (init_dns_base(main_ctl) != 0) {
		event_base_free(main_ctl->connect_base);
		free(main_ctl);
		exit(1);
	}
}

/**
 * @brief Frees resources associated with the main control structure
 *
 * This function handles cleanup of the main control resources.
 * It should be called when shutting down the application to prevent memory leaks.
 */
static void free_main_control()
{
	if (main_ctl) {
		free(main_ctl);
		main_ctl = NULL;
	}
}

/**
 * @brief Clears the main control data structure and resets associated resources
 * 
 * This function frees and resets the main control structure, cleaning up any
 * allocated resources and returning the control state to its initial state.
 */
static void clear_main_control()
{
	// Validate main control exists
	if (!main_ctl) {
		debug(LOG_ERR, "Cannot clear NULL main control");
		return;
	}

	// Clear event timers
	if (main_ctl->ticker_ping) {
		if (evtimer_del(main_ctl->ticker_ping) < 0) {
			debug(LOG_ERR, "Failed to delete ticker ping timer");
		}
		main_ctl->ticker_ping = NULL;
	}

	if (main_ctl->tcp_mux_ping_event) {
		if (evtimer_del(main_ctl->tcp_mux_ping_event) < 0) {
			debug(LOG_ERR, "Failed to delete TCP mux ping timer"); 
		}
		main_ctl->tcp_mux_ping_event = NULL;
	}

	// Reset connection state
	set_xfrpc_status(false);
	is_login = 0;
	pong_time = 0;

	// Clean up resources
	clear_all_proxy_client();
	free_crypto_resources();

	// Reinitialize TCP multiplexing if enabled
	struct common_conf *conf = get_common_config();
	if (conf && conf->tcp_mux) {
		uint32_t session_id = get_next_session_id();
		init_tmux_stream(&main_ctl->stream, session_id, INIT);
		debug(LOG_DEBUG, "Reinitialized TCP mux stream with session ID %u", session_id);
	}
}

/**
 * @brief Closes the main control of xfrpc
 *
 * This function is responsible for shutting down the main control functionality
 * and cleaning up any associated resources.
 *
 * @return void
 */
void close_main_control()
{
	if (!main_ctl) {
		debug(LOG_ERR, "main_ctl is NULL");
		return;
	}

	// Clean up resources and state
	clear_main_control();

	// Free event bases
	if (main_ctl->connect_base) {
		if (event_base_dispatch(main_ctl->connect_base) < 0) {
			debug(LOG_ERR, "event_base_dispatch failed");
		}

		if (main_ctl->dnsbase) {
			evdns_base_free(main_ctl->dnsbase, 0);
			main_ctl->dnsbase = NULL;
		}

		event_base_free(main_ctl->connect_base);
		main_ctl->connect_base = NULL;
	}

	// Free the main control structure
	free_main_control();
}

void run_control() 
{
	start_base_connect();
}


