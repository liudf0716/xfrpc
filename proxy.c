#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>


#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"
#include "config.h"

struct proxy *
new_proxy_obj(struct bufferevent *bev)
{
	struct proxy *p = (struct proxy *)calloc(1, sizeof(struct proxy));
	assert(p);
	p->bev = bev;
	p->remote_data_port = -1;
	p->proxy_name = NULL;
	return p;
}

void 
free_proxy_obj(struct proxy *p)
{
	SAFE_FREE(p->proxy_name);
	SAFE_FREE(p);
}
