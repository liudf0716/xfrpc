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
#include "config.h"

struct proxy *new_proxy_buf(struct bufferevent *bev)
{
	struct proxy *p = (struct proxy *)calloc(1, sizeof(struct proxy));
	assert(p);
	p->bev = bev;
	return p;
}