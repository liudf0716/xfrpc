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

#ifdef HAS_SNAPPY
#include <snappy-c.h>
#endif

#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"
#include "config.h"
#include "tcpmux.h"
#include "control.h"
#include "crypto_stream.h"

/** @brief Maximum buffer size for SOCKS5 protocol data */
#define SOCKS5_BUFFER_SIZE 2048

/** @brief Maximum domain name length for SOCKS5 address parsing */
#define SOCKS5_MAX_DOMAIN_LEN 253

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

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
 * Optimized to use Libevent's evbuffer directly, avoiding unnecessary 
 * allocations and memmove operations.
 */
void handle_socks5(struct proxy_client *client, struct bufferevent *bev, uint32_t len)
{
	if (!client || !bev || len == 0) {
		return;
	}

	struct common_conf *c_conf = get_common_config();
	struct evbuffer *src = bufferevent_get_input(bev);

	/* STAGE 1: Data forwarding for established sessions */
	if (client->state == SOCKS5_ESTABLISHED) {
		if (client->local_proxy_bev) {
			struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
			evbuffer_zc_transfer(src, dst, len);
		}
		return;
	}

	/* STAGE 2: Protocol Handshake Parsing */
	
	/* Consume what we just received into our temporary parsing buffer 
	 * if it's not enough to be handled immediately. */
	if (socks5_buf_ensure(client, client->socks5_buf_len + len) < 0) {
		return;
	}

	size_t nr = bufferevent_read(bev,
		client->socks5_buf + client->socks5_buf_len, len);
	if (nr == 0) return;
	client->socks5_buf_len += nr;

	while (client->socks5_buf_len > 0) {
		uint8_t *buf = client->socks5_buf;
		size_t buf_len = client->socks5_buf_len;

		if (client->state == SOCKS5_INIT) {
			if (buf_len < 3) break; // Need more data

			if (buf[0] != 0x05) {
				debug(LOG_ERR, "Unsupported SOCKS version: 0x%02x", buf[0]);
				client->state = CLOSED;
				return;
			}

			/* Respond: 選中 NO AUTH (0x00) */
			uint8_t resp[2] = {0x05, 0x00};
			if (!c_conf->tcp_mux) {
				bufferevent_write(client->ctl_bev, resp, 2);
			} else {
				struct evbuffer *tmp = evbuffer_new();
				if (tmp) {
					evbuffer_add(tmp, resp, 2);
					tmux_stream_write(client->ctl_bev, tmp, &client->stream);
					evbuffer_free(tmp);
				}
			}
			bufferevent_flush(client->ctl_bev, EV_WRITE, BEV_FLUSH);

			size_t consumed = 2 + buf[1]; // VER + NMETHODS + METHODS
			if (buf_len < consumed) {
				/* The full list of methods hasn't arrived yet. 
				 * SOCKS5 init greeting is VER(1) + NMETHODS(1) + METHODS(N) */
				break; 
			}

			memmove(buf, buf + consumed, buf_len - consumed);
			client->socks5_buf_len -= consumed;
			client->state = SOCKS5_HANDSHAKE;
			continue; // Check if next state's data is already in pipe
		}

		if (client->state == SOCKS5_HANDSHAKE) {
			if (buf_len < 4) break;

			/* Validate SOCKS5 Request Header: VER(1), CMD(1), RSV(1) */
			if (buf[0] != 0x05 || buf[1] != 0x01 || buf[2] != 0x00) {
				debug(LOG_ERR, "Invalid SOCKS5 request header: %02x %02x %02x", 
				      buf[0], buf[1], buf[2]);
				client->state = CLOSED;
				return;
			}

			int addr_offset = 0;
			if (!parse_socks5_addr(buf + 3, buf_len - 3, &addr_offset, &client->remote_addr)) {
				break; // Wait for more address data
			}

			size_t total_request_len = 3 + addr_offset;

			client->local_proxy_bev = socks5_proxy_connect(client, &client->remote_addr);
			if (!client->local_proxy_bev) {
				debug(LOG_ERR, "Failed to connect to SOCKS5 backend");
				return;
			}

			memmove(buf, buf + total_request_len, buf_len - total_request_len);
			client->socks5_buf_len -= total_request_len;

			/* Forward any trailing payload data that was packed with the handshake */
			if (client->socks5_buf_len > 0) {
				struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
				evbuffer_add(dst, client->socks5_buf, client->socks5_buf_len);
				client->socks5_buf_len = 0;
			}

			client->state = SOCKS5_CONNECT;
			break;
		}

		break; // No state matched or data exhausted
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
/**
 * @brief Apply encryption and compression to data for sending (client→server)
 *
 * Compresses with snappy (if enabled), then encrypts with AES-128-CFB.
 * On first call, prepends 16-byte IV to the output.
 *
 * @param client Proxy client with crypto contexts
 * @param src Source evbuffer (raw data)
 * @param dst Destination evbuffer (encrypted/compressed data)
 */
static void crypto_encode_evbuffer(struct proxy_client *client,
                                   struct evbuffer *src, struct evbuffer *dst)
{
	size_t len = evbuffer_get_length(src);
	if (len == 0) return;

	/* Pull data into contiguous buffer */
	uint8_t *data = evbuffer_pullup(src, len);
	if (!data) return;

	/* Snappy compression: output may be larger than input */
	size_t comp_len = 0;
	uint8_t *comp_data = NULL;
#ifdef HAS_SNAPPY
	if (client->use_compression && client->snappy_c) {
		size_t max_comp = snappy_max_compressed_length(len);
		comp_data = malloc(max_comp);
		if (comp_data) {
			if (snappy_compress_data(client->snappy_c, data, len,
			                         comp_data, &max_comp) == 0) {
				comp_len = max_comp;
			} else {
				free(comp_data);
				comp_data = NULL;
			}
		}
	}
#endif

	/* Use compressed data if available, otherwise raw */
	uint8_t *work_data = comp_data ? comp_data : data;
	size_t work_len = comp_data ? comp_data ? comp_len : len : len;

	/* Encryption: encrypt in-place, prepend IV on first call */
	if (client->use_encryption && client->encrypt_ctx) {
		/* Prepend IV on first call */
		if (!crypto_writer_iv_sent(client->encrypt_ctx)) {
			uint8_t iv[16];
			crypto_get_iv(client->encrypt_ctx, iv);
			evbuffer_add(dst, iv, 16);
			crypto_writer_set_iv_sent(client->encrypt_ctx);
		}
		crypto_encrypt(client->encrypt_ctx, work_data, work_len);
	}

	evbuffer_add(dst, work_data, work_len);
	evbuffer_drain(src, len);

	free(comp_data);
}

/**
 * @brief Apply decryption and decompression to data for receiving (server→client)
 *
 * On first call, reads 16-byte IV from input.
 * Decrypts with AES-128-CFB, then decompresses with snappy.
 *
 * @param client Proxy client with crypto contexts
 * @param src Source evbuffer (encrypted/compressed data)
 * @param dst Destination evbuffer (raw data)
 */
static void crypto_decode_evbuffer(struct proxy_client *client,
                                   struct evbuffer *src, struct evbuffer *dst)
{
	size_t len = evbuffer_get_length(src);
	if (len == 0) return;

	/* Read IV on first call */
	if (client->use_encryption && client->decrypt_ctx &&
	    !crypto_reader_iv_received(client->decrypt_ctx)) {
		if (len < 16) return; /* Need more data for IV */
		uint8_t iv[16];
		evbuffer_remove(src, iv, 16);
		crypto_set_iv(client->decrypt_ctx, iv);
		crypto_reader_set_iv_received(client->decrypt_ctx);
		len -= 16;
		if (len == 0) return;
	}

	/* Pull remaining data */
	uint8_t *data = evbuffer_pullup(src, len);
	if (!data) return;

	/* Make a copy since we'll modify in-place */
	uint8_t *work_data = malloc(len);
	if (!work_data) return;
	memcpy(work_data, data, len);
	evbuffer_drain(src, len);

	/* Decrypt */
	if (client->use_encryption && client->decrypt_ctx) {
		crypto_decrypt(client->decrypt_ctx, work_data, len);
	}

	/* Decompress */
#ifdef HAS_SNAPPY
	if (client->use_compression && client->snappy_d) {
		size_t uncomp_len = 0;
		if (snappy_uncompressed_length((const char *)work_data, len, &uncomp_len) == SNAPPY_OK &&
		    uncomp_len > 0) {
			uint8_t *uncomp_data = malloc(uncomp_len);
			if (uncomp_data) {
				size_t out_len = uncomp_len;
				if (snappy_decompress_data(client->snappy_d, work_data, len,
				                           uncomp_data, uncomp_len, &out_len) == 0) {
					evbuffer_add(dst, uncomp_data, out_len);
					free(uncomp_data);
					free(work_data);
					return;
				}
				free(uncomp_data);
			}
		}
	}
#endif

	evbuffer_add(dst, work_data, len);
	free(work_data);
}

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

	/* Apply encryption/compression if enabled */
	if (client->use_encryption || client->use_compression) {
		struct evbuffer *processed = evbuffer_new();
		if (!processed) return;
		crypto_encode_evbuffer(client, src, processed);

		if (!c_conf->tcp_mux) {
			struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
			evbuffer_add_buffer(dst, processed);
			evbuffer_free(processed);
			return;
		}

		/* For tcp_mux, write through tmux stream */
		while (evbuffer_get_length(processed) > 0) {
			int written = tmux_stream_write(client->ctl_bev, processed, &client->stream);
			if (written < 0) {
				debug(LOG_INFO, "Stream %u: tmux_stream_write error %d",
				      client->stream.id, written);
				evbuffer_free(processed);
				del_proxy_client_by_stream_id(client->stream.id);
				return;
			}
			if (written == 0) {
				/* Window exhausted - put remaining back */
				struct evbuffer *input = bufferevent_get_input(bev);
				evbuffer_prepend(input, evbuffer_pullup(processed, -1),
				                 evbuffer_get_length(processed));
				evbuffer_free(processed);
				bufferevent_disable(bev, EV_READ);
				return;
			}
		}
		evbuffer_free(processed);
		return;
	}

	/* No encryption/compression - original path */
	if (!c_conf->tcp_mux) {
		struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
		evbuffer_add_buffer(dst, src);
		return;
	}

	while (evbuffer_get_length(src) > 0) {
		int written = tmux_stream_write(client->ctl_bev, src, &client->stream);
		if (written < 0) {
			debug(LOG_INFO, "Stream %u: tmux_stream_write error %d, cleaning up",
			      client->stream.id, written);
			del_proxy_client_by_stream_id(client->stream.id);
			return;
		}

		if (written == 0) {
			bufferevent_disable(bev, EV_READ);
			debug(LOG_DEBUG, "Stream %u: send_window exhausted, disabling EV_READ",
			      client->stream.id);
			return;
		}
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

	/* Apply decryption/decompression if enabled */
	if (client->use_encryption || client->use_compression) {
		struct evbuffer *processed = evbuffer_new();
		if (!processed) return;
		crypto_decode_evbuffer(client, src, processed);

		struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
		evbuffer_add_buffer(dst, processed);
		evbuffer_free(processed);
		return;
	}

	/* No encryption/decompression - original path */
	if (!c_conf->tcp_mux) {
		struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
		evbuffer_add_buffer(dst, src);
		return;
	}

	debug(LOG_ERR, "impossible to reach here");
}

/**
 * @brief SOCKS5 server-to-client proxy callback (used when tcp_mux is disabled)
 */
void socks5_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	if (len == 0) return;

	handle_socks5(client, bev, (uint32_t)len);
}

/**
 * @brief XDPI server-to-client proxy callback (used when tcp_mux is disabled)
 */
void xdpi_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	if (len == 0) return;

	handle_xdpi(client, bev, (uint32_t)len);
}
