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

#define IP_LEN 16

static struct ftp_pasv *new_ftp_pasv();
static void free_ftp_pasv(struct ftp_pasv *fp);

// read from client-working host port
void ftp_proxy_c2s_cb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = (struct bufferevent *)ctx;
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (len < 0)
		return;

	unsigned char *buf = calloc(1, len);
	assert(buf);
	size_t read_n = 0;
	read_n = evbuffer_copyout(src, buf, len);
	char *dbg_buf = calloc(1, read_n * 7 + 1);
	assert(dbg_buf);
	unsigned int i = 0;
	for(i = 0; i<read_n && ((2 * i) < (read_n * 2 + 1)); i++) {
		snprintf(dbg_buf + 7*i, 8, "%3u[%c] ", (unsigned char)buf[i], (unsigned char)buf[i]);
	}
	debug(LOG_DEBUG, "RECV ctl byte:%s", dbg_buf);
	debug(LOG_DEBUG, "RECV ctl stri:%s", buf);
	SAFE_FREE(dbg_buf);
	SAFE_FREE(buf);

	dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src);

	return;
}

void ftp_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
	tcp_proxy_s2c_cb(bev, ctx);
}

int unpack

static struct ftp_pasv *new_ftp_pasv()
{
	struct ftp_pasv *fp = (struct ftp_pasv *)calloc(1, sizeof(struct ftp_pasv));
	assert(fp);

	fp->ftp_server_ip = NULL;
	fp->ftp_server_port = -1;
	fp->code = -1;
	fp->msg = NULL;

	return fp;	 
}

static void free_ftp_pasv(struct ftp_pasv *fp)
{
	if (!fp)
		return;

	SAFE_FREE(fp->ftp_server_ip);
	SAFE_FREE(fp->msg);
	SAFE_FREE(fp);
	fp = NULL;
}