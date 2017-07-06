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

#define FTP_PRO_BUF 		256
#define FTP_PASV_PORT_BLOCK 256

static struct ftp_pasv *new_ftp_pasv();
static void free_ftp_pasv(struct ftp_pasv *fp);
static struct ftp_pasv * pasv_unpack(char *data);
static size_t pasv_pack(struct ftp_pasv *fp, char **pack_p);

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
	struct ftp_pasv *fp = pasv_unpack((char *)buf);
	if (fp) {
		debug(LOG_DEBUG, "ftp unpacked pasv protocol");
	}
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

static struct ftp_pasv *pasv_unpack(char *data)
{
	char cd_buf[4] = {0};
	snprintf(cd_buf, 4, "%s", data);
	int code = atoi(cd_buf);
	if (code != 227 && code != 211 && code != 229)
		return NULL;

	struct ftp_pasv *fp = new_ftp_pasv();
	assert(fp);
	int unpacked = 0;

	fp->code = code;
	switch(fp->code) {
		case 227:
		{
			int i = 0, ip_i = 0, port_i = 0, ip_start = 0, comma_n = 0;
			char port[2][4] = { {0}, {0} };
			for (i=0; i<strlen(data) && ip_i<IP_LEN; i++) {
				if (data[i] == '(') {
					ip_start = 1;
					continue;
				} 
				if (! ip_start)
					continue;

				if (data[i] == ')')
					break;

				if (data[i] == ','){
					comma_n++;
					port_i = 0;
					if (comma_n < 4){
						fp->ftp_server_ip[ip_i] = '.';
						ip_i++;
					}
					continue;
				}

				if (comma_n >= 4 && port_i < 4) {
					port[comma_n - 4][port_i] = data[i];
					port_i++;
					continue;
				}
				fp->ftp_server_ip[ip_i] = data[i];
				ip_i++;
			}

			fp->ftp_server_port = atoi(port[0]) * FTP_PASV_PORT_BLOCK + atoi(port[1]);
			debug(LOG_DEBUG, "ftp pasv unpack:[%s:%d]", fp->ftp_server_ip, fp->ftp_server_port);
			unpacked = 1;
			break;
		}
		default:
			break;
	}

	if (! unpacked)
		free_ftp_pasv(fp);

	return fp;
}

// the value returned need FREE after using
static size_t pasv_pack(struct ftp_pasv *fp, char **pack_p)
{
	*pack_p = (char *)calloc(1, FTP_PRO_BUF);
	assert(*pack_p);

	switch (fp->code){
		case 227:
		{
			char ftp_ip[IP_LEN] = {0};
			int i =0;
			for (i=0; i<strlen(fp->ftp_server_ip) && i < IP_LEN; i++) {
				if (fp->ftp_server_ip[i] == '.') {
					ftp_ip[i] = ',';
					continue;
				}
				
				ftp_ip[i] = fp->ftp_server_ip[i];
			}
			snprintf(*pack_p, 
				FTP_PRO_BUF, 
				"227 Entering Passive Mode (%s,%d,%d)", 
				ftp_ip, 
				fp->ftp_server_port / FTP_PASV_PORT_BLOCK, 
				fp->ftp_server_port % FTP_PASV_PORT_BLOCK);
			break;
		}
		default:
			debug(LOG_DEBUG, "ftp pasv protocol data not supportted in pasv_pack");
			break;
	}

	return strlen(*pack_p);
}

static struct ftp_pasv *new_ftp_pasv()
{
	struct ftp_pasv *fp = (struct ftp_pasv *)calloc(1, sizeof(struct ftp_pasv));
	if (! fp)
		return NULL;

	memset(fp->ftp_server_ip, 0, IP_LEN);
	fp->ftp_server_port = -1;
	fp->code = -1;

	return fp;	 
}

static void free_ftp_pasv(struct ftp_pasv *fp)
{
	if (!fp)
		return;

	SAFE_FREE(fp->ftp_server_ip);
	SAFE_FREE(fp);
	fp = NULL;
}