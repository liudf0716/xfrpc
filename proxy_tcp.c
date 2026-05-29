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

/** @brief Maximum buffer size for SOCKS5 protocol data */
#define SOCKS5_BUFFER_SIZE 2048

/** @brief Maximum domain name length for SOCKS5 address parsing */
#define SOCKS5_MAX_DOMAIN_LEN 253

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/**
 * @brief Validates if a buffer contains a valid SOCKS5 protocol header
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
 * @brief Parse SOCKS5 address structure from a contiguous buffer
 *
 * @param buf    Buffer containing the SOCKS5 address data
 * @param len    Total length of data available in buf
 * @param offset Returns number of bytes consumed from buf
 * @param addr   Output parameter for parsed address structure
 * @return 1 on success, 0 on failure/invalid format
 */
static int parse_socks5_addr(const uint8_t *buf, int len, int *offset,
							struct socks5_addr *addr)
{
	assert(addr && buf && offset);
	assert(len > 0);

	memset(addr, 0, sizeof(struct socks5_addr));
	int pos = 0;

	addr->type = buf[pos++];

	switch(addr->type) {
		case 0x01:  // IPv4: 4 bytes addr + 2 bytes port = 7 total
			if (len < 7) return 0;
			memcpy(addr->addr, buf + pos, 4);
			pos += 4;
			memcpy(&addr->port, buf + pos, 2);
			pos += 2;
			*offset = pos;
			break;

		case 0x04:  // IPv6: 16 bytes addr + 2 bytes port = 19 total
			if (len < 19) return 0;
			memcpy(addr->addr, buf + pos, 16);
			pos += 16;
			memcpy(&addr->port, buf + pos, 2);
			pos += 2;
			*offset = pos;
			break;

		case 0x03:  // Domain: 1 byte len + domain + 2 bytes port
			if (len < 2) return 0;
			{
				uint8_t domain_len = buf[pos++];
				/* Enstrict bounds: reject domains exceeding SOCKS5_MAX_DOMAIN_LEN
				 * or SOCKS5_ADDRES_LEN to prevent buffer overflow in addr[]. */
				if (domain_len == 0 ||
				    domain_len > SOCKS5_MAX_DOMAIN_LEN ||
				    domain_len > SOCKS5_ADDRES_LEN) {
					debug(LOG_ERR, "SOCKS5 domain length %u out of bounds", domain_len);
					return 0;
				}
				if (len < pos + domain_len + 2) return 0;
				memcpy(addr->addr, buf + pos, domain_len);
				pos += domain_len;
				memcpy(&addr->port, buf + pos, 2);
				pos += 2;
				*offset = pos;
			}
			break;

		default:
			return 0;
	}

	return 1;
}

/**
 * @brief Establish a SOCKS5 proxy connection based on destination address
 */
static struct bufferevent *socks5_proxy_connect(struct proxy_client *client, struct socks5_addr *addr)
{
	struct bufferevent *bev = NULL;

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

			char ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, addr->addr, ip, INET_ADDRSTRLEN);
			debug(LOG_DEBUG, "SOCKS5 connecting to IPv4: %s:%d", ip, ntohs(addr->port));

			connect_result = bufferevent_socket_connect(bev, 
				(struct sockaddr *)&sin, sizeof(sin));
			break;
		}

		case 0x03: // Domain name
			debug(LOG_DEBUG, "SOCKS5 connecting to domain: %.*s:%d", 
				(int)strnlen((char *)addr->addr, SOCKS5_ADDRES_LEN),
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

	bufferevent_setcb(bev, tcp_proxy_c2s_cb, NULL, xfrp_proxy_event_cb, client);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	return bev;
}

/**
 * @brief Ensure the SOCKS5 parser buffer has at least 'need' bytes of capacity.
 * Returns 0 on success, -1 on allocation failure.
 */
static int socks5_buf_ensure(struct proxy_client *client, size_t need)
{
	if (client->socks5_buf_cap >= need)
		return 0;

	size_t new_cap = client->socks5_buf_cap;
	if (new_cap == 0) new_cap = SOCKS5_BUF_INIT_CAP;
	while (new_cap < need) new_cap *= 2;

	uint8_t *new_buf = realloc(client->socks5_buf, new_cap);
	if (!new_buf) {
		debug(LOG_ERR, "Failed to realloc socks5_buf to %zu", new_cap);
		return -1;
	}
	client->socks5_buf = new_buf;
	client->socks5_buf_cap = new_cap;
	return 0;
}

/**
 * @brief Ensure the XDPI parser buffer has at least 'need' bytes of capacity.
 * Returns 0 on success, -1 on allocation failure.
 */
static int xdpi_buf_ensure(struct proxy_client *client, size_t need)
{
	if (client->xdpi_buf_cap >= need)
		return 0;

	size_t new_cap = client->xdpi_buf_cap;
	if (new_cap == 0) new_cap = XDPI_BUF_INIT_CAP;
	while (new_cap < need) new_cap *= 2;

	uint8_t *new_buf = realloc(client->xdpi_buf, new_cap);
	if (!new_buf) {
		debug(LOG_ERR, "Failed to realloc xdpi_buf to %zu", new_cap);
		return -1;
	}
	client->xdpi_buf = new_buf;
	client->xdpi_buf_cap = new_cap;
	return 0;
}

/**
 * @brief Handles SOCKS5 protocol states and data forwarding
 *
 * Reads data directly from the control bev (no rx_ring). Uses per-client
 * socks5_buf for accumulating fragmented handshake/request data.
 */
void handle_socks5(struct proxy_client *client, struct bufferevent *bev, uint32_t len)
{
	if (!client || !bev || len == 0) {
		debug(LOG_ERR, "Invalid parameters in handle_socks5");
		return;
	}

	/* ESTABLISHED: forward payload zero-copy to local proxy */
	if (client->state == SOCKS5_ESTABLISHED) {
		assert(client->local_proxy_bev);
		struct evbuffer *src = bufferevent_get_input(bev);
		struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
		evbuffer_zc_transfer(src, dst, len);
		return;
	}

	/* Accumulate incoming data into per-client socks5_buf */
	if (socks5_buf_ensure(client, client->socks5_buf_len + len) < 0) {
		return;
	}

	size_t nr = bufferevent_read(bev,
		client->socks5_buf + client->socks5_buf_len, len);
	if (nr == 0) return;
	client->socks5_buf_len += nr;

	uint8_t *buf = client->socks5_buf;
	size_t buf_len = client->socks5_buf_len;

	/* INIT: waiting for SOCKS5 greeting (version + nmethods + methods) */
	if (client->state == SOCKS5_INIT && buf_len >= 3) {
		debug(LOG_DEBUG, "Processing SOCKS5 initial handshake, buf_len: %zu", buf_len);

		if (buf[0] != 0x05 || buf[1] != 0x01 || buf[2] != 0x00) {
			debug(LOG_ERR, "Invalid SOCKS5 handshake");
			return;
		}

		/* Send handshake response: no authentication required */
		uint8_t resp[3] = {0x05, 0x00, 0x00};
		int ret = tmux_stream_write(client->ctl_bev, resp, 3, &client->stream);
		if (ret < 0) {
			debug(LOG_ERR, "SOCKS5 handshake write failed: stream %d error %d",
			      client->stream.id, ret);
			return;
		}

		/* Consume consumed bytes from buffer */
		memmove(buf, buf + 3, buf_len - 3);
		client->socks5_buf_len -= 3;
		client->state = SOCKS5_HANDSHAKE;
	}

	/* HANDSHAKE: waiting for CONNECT request */
	buf = client->socks5_buf;
	buf_len = client->socks5_buf_len;
	if (client->state == SOCKS5_HANDSHAKE && buf_len >= 4) {
		debug(LOG_DEBUG, "Processing SOCKS5 connection request, buf_len: %zu", buf_len);

		if (!is_socks5(buf, 3)) {
			debug(LOG_ERR, "Invalid SOCKS5 request format");
			return;
		}

		int offset = 0;
		if (!parse_socks5_addr(buf + 3, buf_len - 3, &offset, &client->remote_addr)) {
			/* Not enough data yet — wait for more */
			return;
		}

		int total_consumed = 3 + offset;

		client->local_proxy_bev = socks5_proxy_connect(client, &client->remote_addr);
		if (!client->local_proxy_bev) {
			debug(LOG_ERR, "Failed to establish proxy connection");
			return;
		}

		/* Discard consumed bytes */
		memmove(buf, buf + total_consumed, buf_len - total_consumed);
		client->socks5_buf_len -= total_consumed;

		/* Flush any remaining buffered data to local proxy */
		if (client->socks5_buf_len > 0 && client->local_proxy_bev) {
			struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
			evbuffer_add(dst, client->socks5_buf, client->socks5_buf_len);
			client->socks5_buf_len = 0;
		}

		client->state = SOCKS5_CONNECT;
	}
}

/**
 * @brief Handles data processing based on XDPI service type verification
 *
 * Reads data directly from the control bev. Uses per-client xdpi_buf for
 * accumulating bytes before protocol verification.
 */
void handle_xdpi(struct proxy_client *client, struct bufferevent *bev, uint32_t len)
{
	if (!client || !bev || len == 0) {
		debug(LOG_ERR, "Invalid parameters in handle_xdpi");
		return;
	}

	/* Already verified: forward zero-copy to local proxy */
	if (client->xdpi_state == XDPI_VERIFIED && client->local_proxy_bev) {
		struct evbuffer *src = bufferevent_get_input(bev);
		struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
		evbuffer_zc_transfer(src, dst, len);
		return;
	}

	/* Accumulate data into per-client xdpi_buf before verification */
	if (xdpi_buf_ensure(client, client->xdpi_buf_len + len) < 0) {
		return;
	}

	size_t nr = bufferevent_read(bev,
		client->xdpi_buf + client->xdpi_buf_len, len);
	if (nr == 0) return;
	client->xdpi_buf_len += nr;

	/* Allocate null-terminated copy for xdpi_engine (uses strstr) */
	uint8_t *data = calloc(client->xdpi_buf_len + 1, sizeof(uint8_t));
	if (!data) {
		debug(LOG_ERR, "Failed to allocate memory for XDPI analysis");
		return;
	}
	memcpy(data, client->xdpi_buf, client->xdpi_buf_len);

	if (xdpi_engine(client, data, client->xdpi_buf_len) < 0) {
		debug(LOG_ERR, "XDPI verification failed for service type %d", client->ps->service_type);
		free(data);
		client->xdpi_state = XDPI_BLOCKED;
		/* Discard buffered data on block */
		client->xdpi_buf_len = 0;
		return;
	}
	free(data);

	/* XDPI verification succeeded, connect if not already connected */
	if (!client->local_proxy_bev) {
		debug(LOG_INFO, "XDPI verification passed, establishing connection for service type %d", 
			  client->ps->service_type);

		if (client->ps->local_ip == NULL || client->ps->local_port == 0) {
			debug(LOG_ERR, "Invalid local IP or port for service type %d", client->ps->service_type);
			client->xdpi_buf_len = 0;
			return;
		}
		client->local_proxy_bev = connect_server(client->base, client->ps->local_ip, client->ps->local_port);

		if (!client->local_proxy_bev) {
			debug(LOG_ERR, "Failed to establish connection to local service on IP %s and port %d", 
				  client->ps->local_ip, client->ps->local_port);
			return;
		}

		bufferevent_setcb(client->local_proxy_bev, tcp_proxy_c2s_cb, NULL, xfrp_proxy_event_cb, client);
		bufferevent_enable(client->local_proxy_bev, EV_READ | EV_WRITE);
	}

	/* Flush buffered data to local proxy, then switch to pass-through */
	if (client->xdpi_buf_len > 0 && client->local_proxy_bev) {
		bufferevent_write(client->local_proxy_bev, client->xdpi_buf, client->xdpi_buf_len);
		client->xdpi_buf_len = 0;
	}
	client->xdpi_state = XDPI_VERIFIED;
}

/**
 * @brief Callback function handling data transfer from client to server in TCP proxy
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
		return;
	}

	struct common_conf *c_conf = get_common_config();
	if (!c_conf->tcp_mux) {
		struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
		evbuffer_add_buffer(dst, src);
		return;
	}

	/* Use evbuffer_peek to iterate over contiguous chunks directly in the
	 * input buffer without copying.  Each chunk is passed to tmux_stream_write
	 * which handles flow control. */
	size_t total_written = 0;
	struct evbuffer_iovec iovec[16];
	while (total_written < len) {
		int nvecs = evbuffer_peek(src, len - total_written, NULL, iovec, 16);
		if (nvecs <= 0) {
			break;
		}

		for (int i = 0; i < nvecs && total_written < len; i++) {
			uint8_t *data = (uint8_t *)iovec[i].iov_base;
			size_t chunk_len = iovec[i].iov_len;
			if (chunk_len == 0) continue;

			int written = tmux_stream_write(client->ctl_bev, data, chunk_len, &client->stream);
			if (written < 0) {
				evbuffer_drain(src, total_written);
				debug(LOG_INFO, "Stream %u: tmux_stream_write error %d, cleaning up",
				      client->stream.id, written);
				del_proxy_client_by_stream_id(client->stream.id);
				return;
			}

			if (written == 0) {
				evbuffer_drain(src, total_written);
				bufferevent_disable(bev, EV_READ);
				debug(LOG_DEBUG, "Stream %u: send_window exhausted, disabling EV_READ",
				      client->stream.id);
				return;
			}

			total_written += written;

			if ((size_t)written < chunk_len) {
				if (client->stream.send_window == 0) {
					evbuffer_drain(src, total_written);
					bufferevent_disable(bev, EV_READ);
					return;
				}
			}
		}
	}

	if (total_written > 0) {
		evbuffer_drain(src, total_written);
	}
}

/**
 * @brief Callback function for handling data transfer from server to client in TCP proxy
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
