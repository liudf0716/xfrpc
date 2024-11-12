/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/** @file proxy_tcp.c
    @brief xfrp proxy udp implemented
    @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
*/

#include <arpa/inet.h>

#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"
#include "config.h"
#include "tcpmux.h"
#include "control.h"

static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int 
base64_encode(const uint8_t *src, int srclen, char *dst)
{
	uint32_t ac = 0;
	int bits = 0;
	int i;
	char *cp = dst;

	for (i = 0; i < srclen; i++) {
		ac = (ac << 8) | src[i];
		bits += 8;
		do {
			bits -= 6;
			*cp++ = base64_table[(ac >> bits) & 0x3f];
		} while (bits >= 6);
	}
	if (bits) {
		*cp++ = base64_table[(ac << (6 - bits)) & 0x3f];
		bits -= 6;
	}
	while (bits < 0) {
		*cp++ = '=';
		bits += 2;
	}
	return cp - dst;
}

static int 
base64_decode(const char *src, int srclen, uint8_t *dst)
{
    uint32_t ac = 0;
	int bits = 0;
	int i;
	uint8_t *bp = dst;

	for (i = 0; i < srclen; i++) {
		const char *p = strchr(base64_table, src[i]);

		if (src[i] == '=') {
			ac = (ac << 6);
			bits += 6;
			if (bits >= 8)
				bits -= 8;
			continue;
		}
		if (p == NULL || src[i] == 0)
			return -1;
		ac = (ac << 6) | (p - base64_table);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*bp++ = (uint8_t)(ac >> bits);
		}
	}
	if (ac & ((1 << bits) - 1))
		return -1;
	return bp - dst;
}

static void
evutil_base64_decode(struct evbuffer *src, struct evbuffer *dst)
{
    uint8_t dbuff[1500] = {0};
    size_t len = evbuffer_get_length(src);
    char *buf = (char *)malloc(len);
    assert(buf != NULL);
    memset(buf, 0, len);
    evbuffer_remove(src, buf, len);
    int decode_len = base64_decode(buf, len, dbuff);
    assert(decode_len > 0 && decode_len < 1500);
    evbuffer_add(dst, dbuff, decode_len);
    free(buf);
}

static void
evutil_base64_encode(struct evbuffer *src, struct evbuffer *dst)
{
    char ebuff[2048] = {0}; // 2048 is enough for base64 encode
    size_t len = evbuffer_get_length(src);
    uint8_t *buf = (uint8_t *)malloc(len);
    assert(buf != NULL);
    memset(buf, 0, len);
    evbuffer_remove(src, buf, len);
    int encode_len = base64_encode(buf, len, ebuff);
    assert(encode_len > 0 && encode_len < 2048);
    evbuffer_add(dst, ebuff, encode_len);
    free(buf);
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