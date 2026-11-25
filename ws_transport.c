// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * WebSocket (ws / wss) transport wrapper for xfrpc using libevent bufferevent_pair.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>

#include <openssl/rand.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>

#include "ws_transport.h"
#include "mongoose.h"
#include "debug.h"

#define WS_MAX_FRAME_CHUNK 32768

enum ws_state {
	WS_CONNECTING = 0,
	WS_HANDSHAKE  = 1,
	WS_OPEN       = 2,
	WS_CLOSED     = 3,
};

struct ws_ctx {
	struct bufferevent *app_bev;  /* pair[0] exposed to caller */
	struct bufferevent *ws_bev;   /* pair[1] internal side */
	struct bufferevent *raw_bev;  /* TCP or TLS bufferevent to frps */
	char               *host;
	int                 port;
	int                 is_wss;
	enum ws_state       state;
	int                 freed;
};

static void ws_ctx_cleanup(struct ws_ctx *ctx)
{
	if (!ctx || ctx->freed)
		return;
	ctx->freed = 1;
	ctx->state = WS_CLOSED;

	if (ctx->raw_bev) {
		bufferevent_setcb(ctx->raw_bev, NULL, NULL, NULL, NULL);
		bufferevent_free(ctx->raw_bev);
		ctx->raw_bev = NULL;
	}
	if (ctx->ws_bev) {
		bufferevent_setcb(ctx->ws_bev, NULL, NULL, NULL, NULL);
		bufferevent_free(ctx->ws_bev);
		ctx->ws_bev = NULL;
	}
	free(ctx->host);
	free(ctx);
}

static void ws_notify_app_event(struct ws_ctx *ctx, short what)
{
	if (!ctx || !ctx->app_bev)
		return;
	if (!bufferevent_pair_get_partner(ctx->ws_bev))
		return;
	bufferevent_event_cb ecb = NULL;
	void *cbarg = NULL;
	bufferevent_getcb(ctx->app_bev, NULL, NULL, &ecb, &cbarg);
	if (ecb)
		ecb(ctx->app_bev, what, cbarg);
}

static int ws_send_frame(struct bufferevent *raw_bev, uint8_t opcode,
                         const uint8_t *payload, size_t len)
{
	if (!raw_bev)
		return -1;

	uint8_t hdr[14];
	size_t hlen = 0;
	hdr[0] = 0x80 | (opcode & 0x0F); /* FIN=1 */

	if (len <= 125) {
		hdr[1] = 0x80 | (uint8_t)len; /* MASK=1 */
		hlen = 2;
	} else if (len <= 65535) {
		hdr[1] = 0x80 | 126;
		hdr[2] = (uint8_t)((len >> 8) & 0xFF);
		hdr[3] = (uint8_t)(len & 0xFF);
		hlen = 4;
	} else {
		hdr[1] = 0x80 | 127;
		uint64_t l64 = (uint64_t)len;
		for (int i = 0; i < 8; i++) {
			hdr[2 + i] = (uint8_t)((l64 >> ((7 - i) * 8)) & 0xFF);
		}
		hlen = 10;
	}

	uint8_t mask[4];
	if (RAND_bytes(mask, 4) != 1) {
		mask[0] = 0x12; mask[1] = 0x34; mask[2] = 0x56; mask[3] = 0x78;
	}
	memcpy(hdr + hlen, mask, 4);
	hlen += 4;

	struct evbuffer *out = bufferevent_get_output(raw_bev);
	evbuffer_add(out, hdr, hlen);

	if (len > 0 && payload) {
		uint8_t *masked = malloc(len);
		if (!masked)
			return -1;
		for (size_t i = 0; i < len; i++) {
			masked[i] = payload[i] ^ mask[i & 3];
		}
		evbuffer_add(out, masked, len);
		free(masked);
	}
	return 0;
}

static void ws_send_upgrade(struct ws_ctx *ctx)
{
	uint8_t rnd[16];
	if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
		memset(rnd, 0x42, sizeof(rnd));
	}
	char b64_key[64];
	mg_base64_encode(rnd, sizeof(rnd), b64_key, sizeof(b64_key));

	struct evbuffer *out = bufferevent_get_output(ctx->raw_bev);
	evbuffer_add_printf(out,
		"GET /~!frp HTTP/1.1\r\n"
		"Host: %s:%d\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Origin: %s://%s:%d\r\n\r\n",
		ctx->host, ctx->port,
		b64_key,
		ctx->is_wss ? "https" : "http",
		ctx->host, ctx->port);
	ctx->state = WS_HANDSHAKE;
	debug(LOG_DEBUG, "[WS] Sent HTTP Upgrade to %s:%d/~!frp", ctx->host, ctx->port);
}

static void ws_flush_app_to_raw(struct ws_ctx *ctx)
{
	if (!ctx || ctx->state != WS_OPEN || !ctx->ws_bev || !ctx->raw_bev)
		return;
	struct evbuffer *in = bufferevent_get_input(ctx->ws_bev);
	while (evbuffer_get_length(in) > 0) {
		size_t avail = evbuffer_get_length(in);
		size_t chunk = avail > WS_MAX_FRAME_CHUNK ? WS_MAX_FRAME_CHUNK : avail;
		uint8_t *buf = malloc(chunk);
		if (!buf)
			return;
		evbuffer_remove(in, buf, chunk);
		ws_send_frame(ctx->raw_bev, 0x02, buf, chunk); /* Binary frame */
		free(buf);
	}
}

static void ws_app_read_cb(struct bufferevent *bev, void *arg)
{
	(void)bev;
	struct ws_ctx *ctx = (struct ws_ctx *)arg;
	if (!ctx || ctx->freed)
		return;
	ws_flush_app_to_raw(ctx);
}

static void ws_app_event_cb(struct bufferevent *bev, short what, void *arg)
{
	(void)bev;
	struct ws_ctx *ctx = (struct ws_ctx *)arg;
	if (!ctx || ctx->freed)
		return;
	if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		if (ctx->state == WS_OPEN && ctx->raw_bev) {
			ws_send_frame(ctx->raw_bev, 0x08, NULL, 0);
		}
		ws_ctx_cleanup(ctx);
	}
}

static void ws_raw_read_cb(struct bufferevent *bev, void *arg)
{
	struct ws_ctx *ctx = (struct ws_ctx *)arg;
	if (!ctx || ctx->freed)
		return;

	struct evbuffer *in = bufferevent_get_input(bev);

	if (ctx->state == WS_HANDSHAKE) {
		struct evbuffer_ptr eoh = evbuffer_search(in, "\r\n\r\n", 4, NULL);
		if (eoh.pos < 0) {
			if (evbuffer_get_length(in) > 16384) {
				debug(LOG_ERR, "[WS] Handshake response too large");
				ws_notify_app_event(ctx, BEV_EVENT_ERROR);
			}
			return;
		}
		size_t hlen = (size_t)eoh.pos + 4;
		char *resp = malloc(hlen + 1);
		if (!resp)
			return;
		evbuffer_remove(in, resp, hlen);
		resp[hlen] = '\0';

		if (strncasecmp(resp, "HTTP/1.1 101", 12) != 0 &&
		    strncasecmp(resp, "HTTP/1.0 101", 12) != 0) {
			debug(LOG_ERR, "[WS] Upgrade failed: %.120s", resp);
			free(resp);
			ws_notify_app_event(ctx, BEV_EVENT_ERROR);
			return;
		}
		free(resp);

		ctx->state = WS_OPEN;
		debug(LOG_INFO, "[WS] WebSocket (%s) connected to %s:%d/~!frp",
		      ctx->is_wss ? "wss" : "ws", ctx->host, ctx->port);
		ws_notify_app_event(ctx, BEV_EVENT_CONNECTED);
		ws_flush_app_to_raw(ctx);
	}

	/* Parse RFC 6455 frames */
	while (ctx->state == WS_OPEN && evbuffer_get_length(in) >= 2) {
		uint8_t hdr[14];
		size_t avail = evbuffer_get_length(in);
		evbuffer_copyout(in, hdr, avail < 14 ? avail : 14);

		uint8_t opcode = hdr[0] & 0x0F;
		int masked = (hdr[1] & 0x80) != 0;
		uint64_t plen = hdr[1] & 0x7F;
		size_t hlen = 2;

		if (plen == 126) {
			if (avail < 4) break;
			plen = ((uint64_t)hdr[2] << 8) | hdr[3];
			hlen = 4;
		} else if (plen == 127) {
			if (avail < 10) break;
			plen = 0;
			for (int i = 0; i < 8; i++)
				plen = (plen << 8) | hdr[2 + i];
			hlen = 10;
		}
		if (masked) {
			if (avail < hlen + 4) break;
			hlen += 4;
		}
		if (avail < hlen + plen)
			break;

		evbuffer_drain(in, hlen);
		uint8_t *payload = NULL;
		if (plen > 0) {
			payload = malloc((size_t)plen);
			if (!payload)
				return;
			evbuffer_remove(in, payload, (size_t)plen);
			if (masked) {
				const uint8_t *mkey = hdr + (hlen - 4);
				for (uint64_t i = 0; i < plen; i++)
					payload[i] ^= mkey[i & 3];
			}
		}

		if (opcode == 0x08) {
			/* Close frame */
			free(payload);
			ws_notify_app_event(ctx, BEV_EVENT_EOF);
			return;
		} else if (opcode == 0x09) {
			/* Ping -> Pong */
			ws_send_frame(ctx->raw_bev, 0x0A, payload, (size_t)plen);
		} else if (opcode == 0x02 || opcode == 0x01 || opcode == 0x00) {
			/* Binary / Text / Continuation -> forward to app_bev */
			if (plen > 0 && ctx->ws_bev && bufferevent_pair_get_partner(ctx->ws_bev)) {
				bufferevent_write(ctx->ws_bev, payload, (size_t)plen);
			}
		}
		free(payload);
	}
}

static void ws_raw_event_cb(struct bufferevent *bev, short what, void *arg)
{
	(void)bev;
	struct ws_ctx *ctx = (struct ws_ctx *)arg;
	if (!ctx || ctx->freed)
		return;

	if (what & BEV_EVENT_CONNECTED) {
		ws_send_upgrade(ctx);
		return;
	}

	if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		debug(LOG_DEBUG, "[WS] Underlying connection closed/error (what=0x%x)", what);
		ws_notify_app_event(ctx, what);
	}
}

struct bufferevent *ws_wrap_bev(struct event_base *base,
                                struct bufferevent *raw_bev,
                                const char *host, int port, int is_wss)
{
	if (!base || !raw_bev || !host) {
		if (raw_bev) bufferevent_free(raw_bev);
		return NULL;
	}

	struct bufferevent *pair[2] = {NULL, NULL};
	if (bufferevent_pair_new(base, BEV_OPT_CLOSE_ON_FREE, pair) != 0) {
		bufferevent_free(raw_bev);
		return NULL;
	}

	struct ws_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		bufferevent_free(pair[0]);
		bufferevent_free(pair[1]);
		bufferevent_free(raw_bev);
		return NULL;
	}

	ctx->app_bev = pair[0];
	ctx->ws_bev = pair[1];
	ctx->raw_bev = raw_bev;
	ctx->host = strdup(host);
	ctx->port = port;
	ctx->is_wss = is_wss;
	ctx->state = WS_CONNECTING;

	bufferevent_setcb(ctx->ws_bev, ws_app_read_cb, NULL, ws_app_event_cb, ctx);
	bufferevent_enable(ctx->ws_bev, EV_READ | EV_WRITE);

	bufferevent_setcb(ctx->raw_bev, ws_raw_read_cb, NULL, ws_raw_event_cb, ctx);
	bufferevent_enable(ctx->raw_bev, EV_READ | EV_WRITE);

	return ctx->app_bev;
}
