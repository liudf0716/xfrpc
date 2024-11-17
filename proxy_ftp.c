// Standard C library headers
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>

// System/Network headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>

// libevent headers
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/event.h>

// Project headers
#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"
#include "config.h"
#include "client.h"

#define FTP_PRO_BUF         256  // Buffer size for FTP protocol messages
#define FTP_PASV_PORT_BLOCK 256  // Block size for PASV port calculation

static struct ftp_pasv *new_ftp_pasv(void);
static void free_ftp_pasv(struct ftp_pasv *fp);
static struct ftp_pasv *pasv_unpack(char *data);
static size_t pasv_pack(struct ftp_pasv *fp, char **pack_p);

/**
 * Sets up FTP data proxy tunnel by configuring local and remote endpoints
 * 
 * @param ftp_proxy_name Base proxy service name
 * @param local_fp Local FTP PASV connection info
 * @param remote_fp Remote FTP PASV connection info
 */
void set_ftp_data_proxy_tunnel(const char *ftp_proxy_name, 
							 struct ftp_pasv *local_fp, 
							 struct ftp_pasv *remote_fp)
{
	struct proxy_service *ps = NULL;
	char *ftp_data_proxy_name = get_ftp_data_proxy_name(ftp_proxy_name);

	struct proxy_service *p_services = get_all_proxy_services();
	HASH_FIND_STR(p_services, ftp_data_proxy_name, ps);
	if (!ps) {
		debug(LOG_ERR, "Error: FTP data proxy not found in proxy service queue");
		goto cleanup;
	}

	ps->local_port = local_fp->ftp_server_port;
	ps->local_ip = strdup(local_fp->ftp_server_ip);
	assert(ps->local_ip);
	ps->remote_port = remote_fp->ftp_server_port;

	debug(LOG_DEBUG, "Set FTP proxy DATA port [local:remote] = [%d:%d]", 
		  ps->local_port, ps->remote_port);

cleanup:
	free(ftp_data_proxy_name);
}

/**
 * Handles client to server FTP communication
 * Processes PASV mode responses and sets up data connections
 */
void ftp_proxy_c2s_cb(struct bufferevent *bev, void *ctx)
{
	struct proxy *p = (struct proxy *)ctx;
	assert(p);
	struct bufferevent *partner = p->bev;
	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	if (len <= 0) return;

	unsigned char *buf = calloc(1, len);
	assert(buf);
	
	size_t read_n = evbuffer_remove(src, buf, len);
	struct ftp_pasv *local_fp = pasv_unpack((char *)buf);

	if (local_fp) {
		struct common_conf *c_conf = get_common_config();
		if (!c_conf->server_addr) {
			debug(LOG_ERR, "Error: FTP proxy missing server IP");
			exit(1);
		}

		// Create and configure remote PASV response
		struct ftp_pasv *r_fp = new_ftp_pasv();
		r_fp->code = local_fp->code;
		strncpy(r_fp->ftp_server_ip, c_conf->server_addr, IP_LEN);
		r_fp->ftp_server_port = p->remote_data_port;

		if (r_fp->ftp_server_port <= 0) {
			debug(LOG_ERR, "Error: Remote FTP data port not initialized");
			goto cleanup;
		}

		// Pack and send modified PASV response
		char *pasv_msg = NULL;
		size_t pack_len = pasv_pack(r_fp, &pasv_msg);
		if (!pack_len) {
			debug(LOG_ERR, "Error: FTP proxy PASV response creation failed");
			SAFE_FREE(pasv_msg);
			goto cleanup;
		}

		set_ftp_data_proxy_tunnel(p->proxy_name, local_fp, r_fp);
		evbuffer_add(bufferevent_get_output(partner), pasv_msg, pack_len);
		SAFE_FREE(pasv_msg);
		free_ftp_pasv(r_fp);
	} else {
		evbuffer_add(bufferevent_get_output(partner), buf, read_n);
	}

cleanup:
	SAFE_FREE(buf);
	free_ftp_pasv(local_fp);
}

/**
 * Handles server to client FTP communication
 */
void ftp_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
	tcp_proxy_s2c_cb(bev, ctx);
}

/**
 * Parses FTP PASV response and extracts IP and port information
 * 
 * @param data Raw FTP response string
 * @return Parsed ftp_pasv structure or NULL if not a PASV response
 */
static struct ftp_pasv *pasv_unpack(char *data)
{
	char cd_buf[4] = {0};
	snprintf(cd_buf, 4, "%s", data);
	int code = atoi(cd_buf);
	if (code != 227 && code != 211 && code != 229)
		return NULL;

	struct ftp_pasv *fp = new_ftp_pasv();
	assert(fp);
	fp->code = code;

	if (code == 227) {
		int ip_i = 0, port_i = 0, comma_n = 0;
		char port[2][4] = {{0}, {0}};
		bool ip_start = false;

		for (size_t i = 0; i < strlen(data) && ip_i < IP_LEN; i++) {
			if (data[i] == '(') {
				ip_start = true;
				continue;
			}
			if (!ip_start)
				continue;
			if (data[i] == ')')
				break;

			if (data[i] == ',') {
				comma_n++;
				port_i = 0;
				if (comma_n < 4) {
					fp->ftp_server_ip[ip_i++] = '.';
				}
				continue;
			}

			if (comma_n >= 4 && port_i < 4) {
				port[comma_n - 4][port_i++] = data[i];
			} else {
				fp->ftp_server_ip[ip_i++] = data[i];
			}
		}

		fp->ftp_server_port = atoi(port[0]) * FTP_PASV_PORT_BLOCK + atoi(port[1]);
		debug(LOG_DEBUG, "FTP PASV unpack: [%s:%d]", fp->ftp_server_ip, fp->ftp_server_port);
	} else {
		free_ftp_pasv(fp);
		return NULL;
	}

	return fp;
}

/**
 * Creates FTP PASV response string from ftp_pasv structure
 * 
 * @param fp Source ftp_pasv structure
 * @param pack_p Pointer to store resulting string
 * @return Length of packed string or 0 on error
 */
static size_t pasv_pack(struct ftp_pasv *fp, char **pack_p)
{
	*pack_p = calloc(1, FTP_PRO_BUF);
	assert(*pack_p);

	if (fp->code == 227) {
		char ftp_ip[IP_LEN] = {0};
		for (size_t i = 0; i < strlen(fp->ftp_server_ip) && i < IP_LEN; i++) {
			ftp_ip[i] = (fp->ftp_server_ip[i] == '.') ? ',' : fp->ftp_server_ip[i];
		}

		size_t pack_len = snprintf(*pack_p, FTP_PRO_BUF,
								 "227 Entering Passive Mode (%s,%d,%d).\n",
								 ftp_ip,
								 fp->ftp_server_port / FTP_PASV_PORT_BLOCK,
								 fp->ftp_server_port % FTP_PASV_PORT_BLOCK);
		return pack_len;
	}

	debug(LOG_DEBUG, "FTP PASV protocol data not supported in pasv_pack");
	free(*pack_p);
	return 0;
}

/**
 * Creates and initializes new ftp_pasv structure
 * 
 * @return Initialized ftp_pasv structure or NULL on allocation failure
 */
static struct ftp_pasv *new_ftp_pasv(void)
{
	struct ftp_pasv *fp = calloc(1, sizeof(struct ftp_pasv));
	if (!fp) return NULL;

	memset(fp->ftp_server_ip, 0, IP_LEN);
	fp->ftp_server_port = -1;
	fp->code = -1;

	return fp;
}

/**
 * Frees ftp_pasv structure
 * 
 * @param fp Structure to free (can be NULL)
 */
static void free_ftp_pasv(struct ftp_pasv *fp)
{
	SAFE_FREE(fp);
}
