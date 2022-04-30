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

// read data from local service
void tcp_proxy_c2s_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	assert(client);
	struct bufferevent *partner = client->ctl_bev;
	assert(partner);
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (len > 0) {
		dst = bufferevent_get_output(partner);
		evbuffer_add_buffer(dst, src);	
	}
}

// read data from frps
void tcp_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy_client *client = (struct proxy_client *)ctx;
	assert(client);
	struct bufferevent *partner = client->local_proxy_bev;
	assert(partner);
	struct evbuffer *src, *dst;
	src = bufferevent_get_input(bev);
	dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src);
}
