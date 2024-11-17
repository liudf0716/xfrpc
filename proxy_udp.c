
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <arpa/inet.h>

#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"
#include "config.h"
#include "tcpmux.h"
#include "control.h"

// Base64 encoding table
static const char BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Encode binary data using base64 encoding
 * @param src Input binary data
 * @param srclen Length of input data
 * @param dst Output buffer for base64 encoded string
 * @return Length of encoded string or -1 on error
 */
static int base64_encode(const uint8_t *src, int srclen, char *dst) 
{
    if (!src || !dst || srclen < 0) return -1;
    
    uint32_t bits_buf = 0;
    int bits_cnt = 0;
    char *out = dst;

    while (srclen--) {
        bits_buf = (bits_buf << 8) | *src++;
        bits_cnt += 8;

        while (bits_cnt >= 6) {
            bits_cnt -= 6;
            *out++ = BASE64_CHARS[(bits_buf >> bits_cnt) & 0x3f];
        }
    }

    // Handle remaining bits
    if (bits_cnt > 0) {
        *out++ = BASE64_CHARS[(bits_buf << (6 - bits_cnt)) & 0x3f];
        
        // Add padding
        while (bits_cnt < 6) {
            *out++ = '=';
            bits_cnt += 2;
        }
    }

    return out - dst;
}

/**
 * Decode base64 encoded string to binary data
 * @param src Input base64 encoded string
 * @param srclen Length of input string
 * @param dst Output buffer for decoded data
 * @return Length of decoded data or -1 on error
 */
static int base64_decode(const char *src, int srclen, uint8_t *dst)
{
    if (!src || !dst || srclen < 0) return -1;

    uint32_t bits_buf = 0;
    int bits_cnt = 0;
    uint8_t *out = dst;

    while (srclen--) {
        char c = *src++;
        
        if (c == '=') {
            bits_buf <<= 6;
            bits_cnt += 6;
            continue;
        }

        const char *p = strchr(BASE64_CHARS, c);
        if (!p) return -1;  // Invalid character

        bits_buf = (bits_buf << 6) | (p - BASE64_CHARS);
        bits_cnt += 6;

        if (bits_cnt >= 8) {
            bits_cnt -= 8;
            *out++ = (bits_buf >> bits_cnt) & 0xff;
        }
    }

    // Check for invalid trailing bits
    if (bits_buf & ((1 << bits_cnt) - 1)) {
        return -1;
    }

    return out - dst;
}

#define UDP_MAX_PACKET_SIZE 1500
#define BASE64_ENCODE_SIZE(x) ((((x) + 2) / 3) * 4 + 1)

/**
 * @brief Decodes base64 encoded data from a source buffer to a destination buffer
 *
 * @param src Source evbuffer containing the base64 encoded data
 * @param dst Destination evbuffer where the decoded data will be stored
 * @return int Returns 0 on success, -1 on failure
 */
static int evutil_base64_decode(struct evbuffer *src, struct evbuffer *dst)
{
    if (!src || !dst) return -1;

    size_t src_len = evbuffer_get_length(src);
    if (src_len == 0) return 0;

    char *src_buf = malloc(src_len);
    if (!src_buf) return -1;

    uint8_t *decode_buf = malloc(src_len); // Base64 decode is always smaller than input
    if (!decode_buf) {
        free(src_buf);
        return -1;
    }

    evbuffer_remove(src, src_buf, src_len);
    int decode_len = base64_decode(src_buf, src_len, decode_buf);
    
    if (decode_len > 0 && decode_len <= UDP_MAX_PACKET_SIZE) {
        evbuffer_add(dst, decode_buf, decode_len);
    }

    free(src_buf);
    free(decode_buf);
    
    return decode_len;
}

/**
 * @brief Encodes data from a source buffer to base64 format in a destination buffer
 *
 * @param src Source evbuffer containing data to be encoded
 * @param dst Destination evbuffer where the base64 encoded data will be stored
 * @return int Returns 0 on success, -1 on failure
 *
 * This function takes the contents of the source evbuffer, performs base64 encoding
 * on the data, and stores the resulting encoded data in the destination evbuffer.
 * The function uses the libevent evbuffer structure for buffer management.
 */
static int evutil_base64_encode(struct evbuffer *src, struct evbuffer *dst)
{
    if (!src || !dst) return -1;

    size_t src_len = evbuffer_get_length(src);
    if (src_len == 0) return 0;
    if (src_len > UDP_MAX_PACKET_SIZE) return -1;

    uint8_t *src_buf = malloc(src_len);
    if (!src_buf) return -1;

    size_t encode_buf_len = BASE64_ENCODE_SIZE(src_len);
    char *encode_buf = malloc(encode_buf_len);
    if (!encode_buf) {
        free(src_buf);
        return -1;
    }

    evbuffer_remove(src, src_buf, src_len);
    int encode_len = base64_encode(src_buf, src_len, encode_buf);
    
    if (encode_len > 0) {
        evbuffer_add(dst, encode_buf, encode_len);
    }

    free(src_buf);
    free(encode_buf);
    
    return encode_len;
}

static int resolve_local_addr(const char *ip, struct sockaddr_in *addr) {
    if (inet_pton(AF_INET, ip, &addr->sin_addr) > 0) {
        return 0;
    }

    struct hostent *host = gethostbyname(ip);
    if (!host) {
        debug(LOG_ERR, "Failed to resolve hostname: %s", ip);
        return -1;
    }

    memcpy(&addr->sin_addr, host->h_addr, host->h_length);
    return 0;
}

/**
 * @brief Handles incoming UDP packets for proxying
 * 
 * This function processes UDP packets received from a client and handles the UDP proxy
 * protocol logic for forwarding the packet to its destination.
 * 
 * @param udp_pkt Pointer to the UDP packet structure containing packet data
 * @param client Pointer to the proxy client structure representing the connected client
 * 
 * @note The function assumes both parameters are valid non-NULL pointers
 */
void handle_udp_packet(struct udp_packet *udp_pkt, struct proxy_client *client) {
    if (!udp_pkt || !client || !client->local_proxy_bev || !client->ps) {
        debug(LOG_ERR, "Invalid parameters in handle_udp_packet");
        return;
    }

    // Decode base64 content
    struct evbuffer *base64_input = evbuffer_new();
    struct evbuffer *decoded_output = evbuffer_new();
    if (!base64_input || !decoded_output) {
        debug(LOG_ERR, "Failed to create evbuffers");
        goto cleanup;
    }

    size_t content_len = strlen(udp_pkt->content);
    if (evbuffer_add(base64_input, udp_pkt->content, content_len) != 0) {
        debug(LOG_ERR, "Failed to add content to base64_input buffer");
        goto cleanup;
    }

    if (evutil_base64_decode(base64_input, decoded_output) < 0) {
        debug(LOG_ERR, "Base64 decoding failed");
        goto cleanup;
    }

    // Setup local address
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(client->ps->local_port);

    if (resolve_local_addr(client->ps->local_ip, &local_addr) != 0) {
        goto cleanup;
    }

    // Forward decoded data
    struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
    if (evbuffer_add_buffer(dst, decoded_output) != 0) {
        debug(LOG_ERR, "Failed to forward decoded data");
    }

cleanup:
    if (base64_input) evbuffer_free(base64_input);
    if (decoded_output) evbuffer_free(decoded_output);
}

/**
 * @brief Callback function for handling UDP proxy client-to-server data transfer
 *
 * This function processes UDP data received from a client, encodes it in base64,
 * packages it into a UDP packet structure, and forwards it to the server.
 * The data is sent either directly or through TCP multiplexing depending on configuration.
 *
 * The process includes:
 * 1. Base64 encoding of received data
 * 2. Creating and populating UDP packet structure
 * 3. Marshalling packet to JSON format
 * 4. Sending data to server based on TCP multiplexing configuration
 *
 * @param bev Bufferevent structure containing the received data
 * @param ctx Context pointer containing proxy client information
 *
 * @note The function handles memory cleanup for all allocated resources
 * @note The function will return early if client parameters are invalid or memory allocation fails
 */
void udp_proxy_c2s_cb(struct bufferevent *bev, void *ctx)
{
    struct proxy_client *client = (struct proxy_client *)ctx;
    if (!client || !client->ctl_bev || !client->ps) {
        debug(LOG_ERR, "Invalid client parameters");
        return;
    }

    struct evbuffer *src = bufferevent_get_input(bev);
    struct evbuffer *base64_output = evbuffer_new();
    if (!base64_output) {
        debug(LOG_ERR, "Failed to create base64 output buffer");
        return;
    }

    // Encode data to base64
    if (evutil_base64_encode(src, base64_output) < 0) {
        debug(LOG_ERR, "Base64 encoding failed");
        evbuffer_free(base64_output);
        return;
    }

    // Create and populate UDP packet structure
    struct udp_packet *udp_pkt = calloc(1, sizeof(struct udp_packet));
    struct udp_addr *raddr = calloc(1, sizeof(struct udp_addr));
    if (!udp_pkt || !raddr) {
        debug(LOG_ERR, "Memory allocation failed");
        goto cleanup;
    }

    udp_pkt->content = (char *)evbuffer_pullup(base64_output, -1);
    udp_pkt->raddr = raddr;
    raddr->addr = client->ps->local_ip;
    raddr->port = client->ps->local_port;

    // Marshal UDP packet to JSON
    char *json_buf = NULL;
    if (new_udp_packet_marshal(udp_pkt, &json_buf) < 0 || !json_buf) {
        debug(LOG_ERR, "UDP packet marshalling failed");
        goto cleanup;
    }

    size_t json_len = strlen(json_buf);
    struct common_conf *c_conf = get_common_config();

    // Send data based on TCP multiplexing configuration
    if (!c_conf->tcp_mux) {
        struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
        if (evbuffer_add(dst, json_buf, json_len) < 0) {
            debug(LOG_ERR, "Failed to add data to output buffer");
        }
    } else {
        uint32_t written = tmux_stream_write(client->ctl_bev, 
                                           (uint8_t *)json_buf, 
                                           json_len, 
                                           &client->stream);
        if (written < json_len) {
            debug(LOG_DEBUG, "Partial write on stream %d: %u/%zu bytes", 
                  client->stream.id, written, json_len);
            bufferevent_disable(bev, EV_READ);
        }
    }

cleanup:
    free(json_buf);
    free(raddr);
    free(udp_pkt);
    evbuffer_free(base64_output);
}

/**
 * @brief Callback function for handling data from server to client in UDP proxy
 * 
 * This function is triggered when data is received from the server and needs to be
 * forwarded to the local UDP client. It reads from the server's bufferevent and
 * writes to the client's local proxy bufferevent.
 *
 * @param bev The bufferevent structure containing data from the server
 * @param ctx Context pointer containing the proxy client structure
 *
 * @note The function will return early if client or local_proxy_bev is NULL
 */
void udp_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
    struct proxy_client *client = (struct proxy_client *)ctx;
    if (!client || !client->local_proxy_bev) {
        debug(LOG_ERR, "Invalid client parameters");
        return;
    }

    struct evbuffer *src = bufferevent_get_input(bev);
    struct evbuffer *dst = bufferevent_get_output(client->local_proxy_bev);
    
    // Forward data from server to local UDP socket
    if (evbuffer_add_buffer(dst, src) != 0) {
        debug(LOG_ERR, "Failed to forward data from server to client");
    }
}