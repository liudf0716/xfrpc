/* vim: set et ts=4 sts=4 sw=4 : */
/*
 * Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
 * 
 * Licensed under the GNU General Public License Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.gnu.org/licenses/gpl-2.0.txt
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

void 
handle_udp_packet(struct udp_packet *udp_pkt, struct proxy_client *client)
{
    // debase64 of udp_pkt->content
    struct evbuffer *base64_input = evbuffer_new();
    size_t content_len = strlen(udp_pkt->content);
    evbuffer_add(base64_input, udp_pkt->content, content_len);
    struct evbuffer *base64_output = evbuffer_new();

    evutil_base64_decode(base64_input, base64_output);
    evbuffer_free(base64_input);

    // send buf content to local_proxy_bev
    struct bufferevent *local_proxy_bev = client->local_proxy_bev;
    assert(local_proxy_bev != NULL);
    // according to client proxy service's local address and port, send buf to local_proxy_bev
    assert(client->ps);
    // if client->ps->local_addr is domain, need to resolve it
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(client->ps->local_port);
    if (inet_pton(AF_INET, client->ps->local_ip, &local_addr.sin_addr) <= 0) {
        // domain
        struct hostent *host = gethostbyname(client->ps->local_ip);
        assert(host != NULL);
        if (host == NULL) {
            debug(LOG_ERR, "gethostbyname %s failed", client->ps->local_ip);
            evbuffer_free(base64_output);
            return;
        }
        memcpy(&local_addr.sin_addr, host->h_addr, host->h_length);
    } 

    // send buf to local_proxy_bev
    struct evbuffer *dst = bufferevent_get_output(local_proxy_bev);
    evbuffer_add_buffer(dst, base64_output);
    evbuffer_free(base64_output);
}

void 
udp_proxy_c2s_cb(struct bufferevent *bev, void *ctx)
{
    struct common_conf  *c_conf = get_common_config();
	struct proxy_client *client = (struct proxy_client *)ctx;
	assert(client);
	struct bufferevent *partner = client->ctl_bev;
	assert(partner);
	struct evbuffer *src = bufferevent_get_input(bev);

	// encode src to base64
    struct evbuffer *base64_output = evbuffer_new();
    evutil_base64_encode(src, base64_output);
    evbuffer_free(src);

    // convert base64_output to udp_packet and json marshal
    struct udp_packet *udp_pkt = (struct udp_packet *)malloc(sizeof(struct udp_packet));
    assert(udp_pkt != NULL);
    memset(udp_pkt, 0, sizeof(struct udp_packet));
    udp_pkt->content = (char *)evbuffer_pullup(base64_output, -1);
    udp_pkt->raddr = (struct udp_addr *)malloc(sizeof(struct udp_addr));
    assert(udp_pkt->raddr != NULL);
    memset(udp_pkt->raddr, 0, sizeof(struct udp_addr));
    udp_pkt->raddr->addr = client->ps->local_ip;
    udp_pkt->raddr->port = client->ps->local_port;
    char *buf = NULL;
    new_udp_packet_marshal(udp_pkt, &buf);
    size_t len = strlen(buf);
    free(udp_pkt->raddr);
    free(udp_pkt);

    if (!c_conf->tcp_mux) {
		struct evbuffer *dst = bufferevent_get_output(partner);
		evbuffer_add(dst, buf, len);
        free(buf);
		return;
	}

	uint32_t nr = tmux_stream_write(partner, (uint8_t *)buf, len, &client->stream);
	if (nr < len) {
		debug(LOG_DEBUG, "stream_id [%d] len is %d tmux_stream_write %d data, disable read", client->stream.id, len, nr);
		bufferevent_disable(bev, EV_READ);
	}
	free(buf);
}

void 
udp_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
    struct proxy_client *client = (struct proxy_client *)ctx;
	assert(client);
}