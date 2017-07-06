#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/event.h>

#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"

// read from client-working host port
void tcp_proxy_c2s_cb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = (struct bufferevent *)ctx;
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (len > 0) {
		dst = bufferevent_get_output(partner);
		evbuffer_add_buffer(dst, src);	
	}
}

void tcp_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = (struct bufferevent *)ctx;
	struct evbuffer *src, *dst;
	src = bufferevent_get_input(bev);
	dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src);
}