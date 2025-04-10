
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/event.h>

#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"
#include "config.h"
#include "tcpmux.h"
#include "control.h"
#include "iod_proto.h"

/** @brief Maximum buffer size for SOCKS5 protocol data */
#define SOCKS5_BUFFER_SIZE 2048

/**
 * @brief Validates if a buffer contains a valid SOCKS5 protocol header
 *
 * Checks if the given buffer contains a valid SOCKS5 protocol header with:
 * - Version: 0x05 (SOCKS5)
 * - Command: 0x01 (CONNECT)
 * - Reserved: 0x00
 *
 * @param buf Buffer containing the SOCKS5 header
 * @param len Length of the buffer
 * @return 1 if valid SOCKS5 header, 0 if invalid
 */
static int is_socks5(const uint8_t *buf, int len)
{
	if (!buf || len < 3) {
		return 0;
	}

	return (buf[0] == 0x05 &&    // SOCKS5 version
			buf[1] == 0x01 &&    // CONNECT command
			buf[2] == 0x00);     // Reserved field
}

/**
 * @brief Parse SOCKS5 address structure from ring buffer
 *
 * Parses a SOCKS5 address structure which can be one of:
 * - IPv4 (type 0x01): 4 bytes address + 2 bytes port
 * - IPv6 (type 0x04): 16 bytes address + 2 bytes port  
 * - Domain (type 0x03): 1 byte length + domain + 2 bytes port
 *
 * @param rb Ring buffer containing the SOCKS5 address data
 * @param len Total length of data in ring buffer
 * @param offset Returns number of bytes processed
 * @param addr Output parameter for parsed address structure
 * @return 1 on success, 0 on failure/invalid format
 */
static int parse_socks5_addr(struct ring_buffer *rb, int len, int *offset, 
							struct socks5_addr *addr)
{
	assert(addr && rb && offset);
	assert(len > 0);

	// Initialize
	memset(addr, 0, sizeof(struct socks5_addr));
	uint8_t buf[256] = {0};  // Increased buffer size to handle domains
	
	// Read address type
	rx_ring_buffer_pop(rb, buf, 1);
	*offset = 1;
	addr->type = buf[0];

	// Parse based on address type
	switch(addr->type) {
		case 0x01:  // IPv4
			if (len < 7) return 0;
			rx_ring_buffer_pop(rb, buf+1, 6);
			memcpy(addr->addr, buf+1, 4);     // IPv4 address
			memcpy(&addr->port, buf+5, 2);    // Port
			*offset = 7;
			break;

		case 0x04:  // IPv6
			if (len < 19) return 0;
			rx_ring_buffer_pop(rb, buf+1, 18);
			memcpy(addr->addr, buf+1, 16);    // IPv6 address
			memcpy(&addr->port, buf+17, 2);   // Port
			*offset = 19;
			break;

		case 0x03:  // Domain name
			if (len < 2) return 0;
			rx_ring_buffer_pop(rb, buf+1, 1); // Domain length
			uint8_t domain_len = buf[1];
			
			if (len < domain_len + 4) return 0;
			rx_ring_buffer_pop(rb, buf+2, domain_len + 2);
			memcpy(addr->addr, buf+2, domain_len);  // Domain
			memcpy(&addr->port, buf+2+domain_len, 2); // Port
			*offset = domain_len + 4;
			break;

		default:
			return 0;
	}

	return 1;
}

/**
 * @brief Establish a SOCKS5 proxy connection based on destination address
 *
 * This function creates and establishes a proxy connection to the target address
 * specified in the SOCKS5 address structure. It supports:
 * - IPv4 addresses (type 0x01)
 * - Domain names (type 0x03) 
 * - IPv6 addresses (type 0x04)
 *
 * @param client Proxy client structure containing event base
 * @param addr SOCKS5 address structure with connection details
 * @return Configured bufferevent on success, NULL on failure
 */
static struct bufferevent *socks5_proxy_connect(struct proxy_client *client, struct socks5_addr *addr)
{
	struct bufferevent *bev = NULL;

	// Create new socket bufferevent
	bev = bufferevent_socket_new(client->base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		debug(LOG_ERR, "Failed to create bufferevent for SOCKS5 proxy");
		return NULL;
	}

	int connect_result = -1;
	switch(addr->type) {
		case 0x01: { // IPv4
			struct sockaddr_in sin = {
				.sin_family = AF_INET,
				.sin_port = addr->port
			};
			memcpy(&sin.sin_addr, addr->addr, 4);

			// Log connection details
			char ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, addr->addr, ip, INET_ADDRSTRLEN);
			debug(LOG_DEBUG, "SOCKS5 connecting to IPv4: %s:%d", ip, ntohs(addr->port));

			connect_result = bufferevent_socket_connect(bev, 
				(struct sockaddr *)&sin, sizeof(sin));
			break;
		}

		case 0x03: // Domain name
			debug(LOG_DEBUG, "SOCKS5 connecting to domain: %s:%d", 
				addr->addr, ntohs(addr->port));
			connect_result = bufferevent_socket_connect_hostname(bev,
				get_main_control()->dnsbase, AF_INET, 
				(char *)addr->addr, ntohs(addr->port));
			break;

		case 0x04: { // IPv6
			struct sockaddr_in6 sin6 = {
				.sin6_family = AF_INET6,
				.sin6_port = addr->port
			};
			memcpy(&sin6.sin6_addr, addr->addr, 16);

			connect_result = bufferevent_socket_connect(bev,
				(struct sockaddr *)&sin6, sizeof(sin6));
			break;
		}

		default:
			debug(LOG_ERR, "Invalid SOCKS5 address type: %d", addr->type);
			bufferevent_free(bev);
			return NULL;
	}

	if (connect_result < 0) {
		debug(LOG_ERR, "Failed to connect SOCKS5 proxy (type %d)", addr->type);
		bufferevent_free(bev);
		return NULL;
	}

	// Setup callbacks and enable bufferevent
	bufferevent_setcb(bev, tcp_proxy_c2s_cb, NULL, xfrp_proxy_event_cb, client);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	return bev;
}

/**
 * @brief Legacy SOCKS5 protocol handler 
 * 
 * This function implements a simplified SOCKS5 protocol handler that supports:
 * - Initial direct connection request (SOCKS5_INIT)
 * - Data forwarding in established state (SOCKS5_ESTABLISHED)
 *
 * @param client The proxy client structure
 * @param rb Ring buffer containing incoming data
 * @param len Length of data in ring buffer
 * @return Number of bytes processed, 0 on error
 * 
 * @deprecated Use handle_socks5() instead which implements full SOCKS5 protocol
 */
uint32_t handle_ss5(struct proxy_client *client, struct ring_buffer *rb, int len) 
{
	uint32_t bytes_processed = 0;

	// Handle established connection state
	if (client->state == SOCKS5_ESTABLISHED) {
		assert(client->local_proxy_bev);
		tx_ring_buffer_write(client->local_proxy_bev, rb, len);
		return len;
	}

	// Handle initial connection request
	if (client->state == SOCKS5_INIT && len >= 7) {
		debug(LOG_DEBUG, "Processing initial SOCKS5 connection request, len: %d", len);

		// Parse destination address
		int addr_len = 0;
		if (!parse_socks5_addr(rb, len, &addr_len, &client->remote_addr)) {
			debug(LOG_ERR, "Failed to parse SOCKS5 address");
			return bytes_processed;
		}

		// Establish proxy connection
		client->local_proxy_bev = socks5_proxy_connect(client, &client->remote_addr);
		if (!client->local_proxy_bev) {
			debug(LOG_ERR, "Failed to establish proxy connection");
			return bytes_processed;
		}

		debug(LOG_DEBUG, "SOCKS5 proxy connection established (parsed %d of %d bytes)", 
			  addr_len, len);
		
		return addr_len;
	}

	return bytes_processed;
}

/**
 * @brief Handles SOCKS5 protocol states and data forwarding
 * 
 * This function implements the SOCKS5 protocol state machine and handles:
 * - Initial handshake (SOCKS5_INIT)
 * - Authentication negotiation (SOCKS5_HANDSHAKE)
 * - Connection establishment (SOCKS5_CONNECT)
 * 
 * @param client The proxy client structure
 * @param rb Ring buffer containing incoming data
 * @param len Length of data in ring buffer
 * @return Number of bytes processed, 0 on error
 */
uint32_t handle_socks5(struct proxy_client *client, struct ring_buffer *rb, int len)
{
	uint32_t nret = 0;

	// Forward data in established connection state
	if (client->state == SOCKS5_CONNECT) {
		assert(client->local_proxy_bev);
		tx_ring_buffer_write(client->local_proxy_bev, rb, len);
		return len;
	}

	// Handle initial SOCKS5 handshake
	if (client->state == SOCKS5_INIT && len >= 3) {
		debug(LOG_DEBUG, "Processing SOCKS5 initial handshake, len: %d", len);
		uint8_t buf[3] = {0};
		rx_ring_buffer_pop(rb, buf, 3);

		if (buf[0] != 0x5 || buf[1] != 0x1 || buf[2] != 0x0) {
			debug(LOG_ERR, "Invalid SOCKS5 handshake");
			return nret;
		}

		// Send handshake response
		buf[1] = 0x0; // No authentication required
		tmux_stream_write(client->ctl_bev, buf, 3, &client->stream);
		client->state = SOCKS5_HANDSHAKE;
		return 3;
	}

	// Handle connection request
	if (client->state == SOCKS5_HANDSHAKE && len >= 10) {
		debug(LOG_DEBUG, "Processing SOCKS5 connection request, len: %d", len);
		uint8_t buf[3] = {0};
		rx_ring_buffer_pop(rb, buf, 3);

		if (!is_socks5(buf, 3)) {
			debug(LOG_ERR, "Invalid SOCKS5 request format");
			return nret;
		}

		int offset = 0;
		if (!parse_socks5_addr(rb, len, &offset, &client->remote_addr)) {
			debug(LOG_ERR, "Failed to parse SOCKS5 address");
			return nret;
		}

		client->local_proxy_bev = socks5_proxy_connect(client, &client->remote_addr);
		if (!client->local_proxy_bev) {
			debug(LOG_ERR, "Failed to establish proxy connection");
			return nret;
		}

		assert(len == offset + 3);
		return len;
	}

	// Handle invalid protocol state
	debug(LOG_ERR, "Invalid SOCKS5 protocol state");
	if (client->local_proxy_bev) {
		bufferevent_free(client->local_proxy_bev);
	}
	return nret;
}

static void handle_iod_set_vip(struct proxy_client *client, struct iod_header *header)
{
	struct in_addr addr;
	addr.s_addr = header->vip4;
	char *vip = inet_ntoa(addr);
	debug(LOG_INFO, "Set VIP: %s", vip);
	
	// Check if dummy0 interface exists
	if (system("ip link show dummy0 > /dev/null 2>&1") != 0) {
		// Create dummy0 interface if it doesn't exist
		system("modprobe dummy");
		system("ip link add dummy0 type dummy");
	}

	// Remove any existing IP addresses from dummy0
	system("ip addr flush dev dummy0");

	// Set the IP address to the VIP
	char cmd[128] = {0};
	snprintf(cmd, sizeof(cmd), "ip addr add %s/32 dev dummy0", vip);
	system(cmd);

	// Ensure the interface is up
	system("ip link set dev dummy0 up");

	debug(LOG_INFO, "VIP %s successfully configured on dummy0", vip);
	header->length = 0;
	header->type = htonl(IOD_SET_VIP_ACK);
	uint32_t written = tmux_stream_write(client->ctl_bev, (uint8_t *)header, sizeof(struct iod_header), &client->stream);
	if (written < sizeof(struct iod_header)) {
		debug(LOG_NOTICE, "Stream %d: Partial write %u/%zu bytes", client->stream.id, written, sizeof(struct iod_header));
	}
	
}

static void handle_iod_get_vip(struct proxy_client *client, struct iod_header *header)
{
	struct in_addr addr;
	addr.s_addr = header->vip4;
	char *vip = inet_ntoa(addr);
	debug(LOG_INFO, "Get VIP: %s", vip);
	char cmd[] = "ip -4 addr show dev dummy0 | grep inet | awk '{print $2}' | cut -d/ -f1";
	FILE *fp = popen(cmd, "r");
	if (!fp) {
		debug(LOG_ERR, "Failed to execute command to get dummy0 IP");
		header->vip4 = 0;
	} else {
		char ip[16] = {0};
		if (fgets(ip, sizeof(ip), fp) != NULL) {
			// Remove trailing newline if present
			char *nl = strchr(ip, '\n');
			if (nl) *nl = '\0';
			
			struct in_addr addr;
			if (inet_aton(ip, &addr) == 0) {
				debug(LOG_ERR, "Failed to convert IP: %s", ip);
				header->vip4 = 0;
			} else {
				header->vip4 = addr.s_addr;
				debug(LOG_INFO, "Retrieved VIP from dummy0: %s", ip);
			}
		} else {
			debug(LOG_ERR, "No IP found on dummy0 interface");
			header->vip4 = 0;
		}
		pclose(fp);
	}

	header->length = 0;
	header->type = htonl(IOD_GET_VIP_ACK);
	uint32_t written = tmux_stream_write(client->ctl_bev, (uint8_t *)header, sizeof(struct iod_header), &client->stream);
	if (written < sizeof(struct iod_header)) {
		debug(LOG_NOTICE, "Stream %d: Partial write %u/%zu bytes", client->stream.id, written, sizeof(struct iod_header));
	}
}

static void handle_local_iod_command(struct proxy_client *client, struct iod_header *header)
{
	uint32_t iod_type = htonl(header->type);
	switch (iod_type) {
	case IOD_SET_VIP:
		debug(LOG_INFO, "Set VIP command");
		handle_iod_set_vip(client, header);
		break;
	case IOD_GET_VIP: 
		debug(LOG_INFO, "Get VIP command");
		handle_iod_get_vip(client, header);
		break;
	default:
		debug(LOG_ERR, "Invalid IOD command: %d", iod_type);
		break;
	}
}

#define IOD_INIT_MAX_LEN 24
uint32_t handle_iod(struct proxy_client *client, struct ring_buffer *rb, int len)
{
	debug(LOG_INFO, "iod state: %d, len: %d", client->iod_state, len);
	if (!client->iod_state && len >= IOD_INIT_MAX_LEN) {
		struct iod_header header;
		rx_ring_buffer_peek(rb, (uint8_t *)&header, IOD_INIT_MAX_LEN);
		if (!is_valid_iod_header(&header)) {
			debug(LOG_INFO, "invalid IOD header, len: %d", len);
			return 0;
		}

		uint32_t iod_type = htonl(header.type);
		if (is_local_iod_command(iod_type)) {
			debug(LOG_INFO, "Local IOD command %d, len: %d", iod_type, len);
			// assert(len == sizeof(struct iod_header));
			rx_ring_buffer_pop(rb, (uint8_t *)&header, sizeof(struct iod_header));
			handle_local_iod_command(client, &header);
			return len;
		}

		if (iod_type != IOD_DATA && len != IOD_INIT_MAX_LEN) {
			debug(LOG_ERR, "Invalid IOD type: %d len is %d", iod_type, len);
			return 0;
		}

		// create a new iod socket connection
		struct in_addr addr;
		addr.s_addr = header.vip4;
		char *iod_addr = inet_ntoa(addr);
		client->local_proxy_bev = connect_server(client->base, iod_addr, client->ps->local_port);
		if (!client->local_proxy_bev) {
			debug(LOG_ERR, "Failed to connect to iod server [%s:%d] bind_addr [%s]", iod_addr, client->ps->local_port, client->ps->bind_addr);
			return 0;
		}

		rx_ring_buffer_pop(rb, (uint8_t *)&header, sizeof(struct iod_header));
		if (client->data_tail) {
			free(client->data_tail);
		}
		client->data_tail = calloc(sizeof(struct iod_header), 1);
		if (!client->data_tail) {
			debug(LOG_ERR, "Failed to allocate memory for data tail");
			return 0;
		}
		header.length = 0;
		memcpy(client->data_tail, &header, sizeof(struct iod_header));
		client->data_tail_size = sizeof(struct iod_header);

		// Setup callbacks and enable bufferevent
		bufferevent_setcb(client->local_proxy_bev, tcp_proxy_c2s_cb, NULL, xfrp_proxy_event_cb, client);
		bufferevent_enable(client->local_proxy_bev, EV_READ | EV_WRITE);
	} else if (client->iod_state) {
		tx_ring_buffer_write(client->local_proxy_bev, rb, len);
	} else {
		debug(LOG_ERR, "Invalid IOD state, len: %d", len);
		return 0;
	}

	return len;
}


/**
 * @brief Callback function handling data transfer from client to server in TCP proxy
 *
 * This function processes data received from the client-side bufferevent and forwards
 * it to the control connection. It supports both regular TCP proxy mode and TCP
 * multiplexing mode.
 *
 * @param bev The bufferevent structure containing client data
 * @param ctx Context pointer containing proxy client information
 *
 * Operation flow:
 * 1. Validates client and control connection
 * 2. Checks for available data in source buffer
 * 3. If TCP multiplexing is disabled, directly forwards data to control connection
 * 4. If TCP multiplexing is enabled, reads data into temporary buffer and writes
 *    to multiplexed stream
 * 
 * @note In multiplexing mode, if partial write occurs, the read event is disabled
 *       to prevent buffer overflow
 */
void tcp_proxy_c2s_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	if (!client || !client->ctl_bev) {
		debug(LOG_ERR, "Invalid client or control connection");
		return;
	}

	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	if (len == 0) {
		debug(LOG_DEBUG, "No data to read from client");
		return;
	}

	struct common_conf *c_conf = get_common_config();
	if (!c_conf->tcp_mux) {
		struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
		evbuffer_add_buffer(dst, src);
		return;
	}

	uint8_t *buf = calloc(1, len);
	if (!buf) {
		debug(LOG_ERR, "Failed to allocate memory for buffer");
		return;
	}

	size_t nr = bufferevent_read(bev, buf, len);
	if (nr != len) {
		debug(LOG_ERR, "Failed to read complete data: expected %zu, got %zu", len, nr);
		free(buf);
		return;
	}

	// add to xdpi engine
	int ret = xdpi_engine(client, buf, len);
	if (ret < 0) {
		debug(LOG_ERR, "XDPI engine failed");
		free(buf);
		return;
	}

	uint32_t written = tmux_stream_write(client->ctl_bev, buf, len, &client->stream);
	if (written < len) {
		debug(LOG_DEBUG, "Stream %d: Partial write %u/%zu bytes, disabling read",
			  client->stream.id, written, len);
		bufferevent_disable(bev, EV_READ);
	}

	free(buf);
}

/**
 * @brief Callback function for handling data transfer from server to client in TCP proxy
 *
 * This function is called when data is available to be read from the server's bufferevent
 * and needs to be forwarded to the client.
 *
 * @param bev The bufferevent structure containing the server's buffer
 * @param ctx The context pointer containing user-defined data (typically proxy session information)
 */
void tcp_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
	struct common_conf *c_conf = get_common_config();
	struct proxy_client *client = (struct proxy_client *)ctx;
	
	if (!client || !client->local_proxy_bev) {
		debug(LOG_ERR, "Invalid client or local proxy connection");
		return;
	}

	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	if (len == 0) {
		debug(LOG_ERR, "No data to read from local service");
		return;
	}

	if (!c_conf->tcp_mux) {
		struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
		evbuffer_add_buffer(dst, src);
		return;
	}

	debug(LOG_ERR, "impossible to reach here");
}
