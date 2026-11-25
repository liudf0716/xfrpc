// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Standard frpc client plugins: http_proxy, static_file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/dns.h>

#include "std_plugins.h"
#include "../client.h"
#include "../control.h"
#include "../debug.h"
#include "../mongoose.h"
#include "../common.h"

struct std_plugin_ctx {
	struct proxy_client *client;
	struct bufferevent  *pair_bev;    /* pair[1] facing xfrpc */
	struct bufferevent  *remote_bev;  /* backend target for http_proxy */
	int                  is_connect;  /* 1 if CONNECT tunnel established */
	int                  headers_done;/* 1 once HTTP request header parsed */
};

int is_std_plugin_proxy(const struct proxy_service *ps)
{
	if (!ps || !ps->plugin) return 0;
	return (strcmp(ps->plugin, "http_proxy") == 0 ||
	        strcmp(ps->plugin, "static_file") == 0);
}

static int check_basic_auth(const char *hdr_start, const char *hdr_end,
                            const char *hdr_name, const char *user, const char *pass)
{
	if ((!user || !*user) && (!pass || !*pass))
		return 1;

	const char *p = hdr_start;
	size_t nlen = strlen(hdr_name);
	while (p < hdr_end) {
		const char *eol = memchr(p, '\n', (size_t)(hdr_end - p));
		size_t llen = eol ? (size_t)(eol - p) : (size_t)(hdr_end - p);
		if (llen > nlen + 1 && strncasecmp(p, hdr_name, nlen) == 0 && p[nlen] == ':') {
			const char *v = p + nlen + 1;
			while (v < p + llen && (*v == ' ' || *v == '\t')) v++;
			if ((size_t)(p + llen - v) > 6 && strncasecmp(v, "Basic ", 6) == 0) {
				v += 6;
				size_t blen = (size_t)(p + llen - v);
				while (blen > 0 && (v[blen - 1] == '\r' || v[blen - 1] == ' '))
					blen--;
				char decoded[512];
				size_t dlen = mg_base64_decode(v, blen, decoded, sizeof(decoded) - 1);
				decoded[dlen] = '\0';
				char expected[512];
				snprintf(expected, sizeof(expected), "%s:%s",
				         user ? user : "", pass ? pass : "");
				return (strcmp(decoded, expected) == 0);
			}
		}
		if (!eol) break;
		p = eol + 1;
	}
	return 0;
}

/* ---------------- http_proxy plugin ---------------- */

static void http_proxy_close(struct std_plugin_ctx *ctx)
{
	if (!ctx) return;
	if (ctx->remote_bev) {
		bufferevent_free(ctx->remote_bev);
		ctx->remote_bev = NULL;
	}
	if (ctx->client) {
		ctx->client->visitor_ctx = NULL;
	}
	if (ctx->pair_bev) {
		bufferevent_setcb(ctx->pair_bev, NULL, NULL, NULL, NULL);
	}
}

static void hp_remote_read_cb(struct bufferevent *bev, void *arg)
{
	struct std_plugin_ctx *ctx = (struct std_plugin_ctx *)arg;
	if (!ctx || !ctx->pair_bev) return;
	evbuffer_add_buffer(bufferevent_get_output(ctx->pair_bev), bufferevent_get_input(bev));
}

static void hp_remote_event_cb(struct bufferevent *bev, short what, void *arg)
{
	struct std_plugin_ctx *ctx = (struct std_plugin_ctx *)arg;
	if (!ctx) return;

	if (what & BEV_EVENT_CONNECTED) {
		if (ctx->is_connect && ctx->pair_bev) {
			static const char ok[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
			bufferevent_write(ctx->pair_bev, ok, sizeof(ok) - 1);
		}
		/* Flush any body/pipeline data already in pair_bev */
		if (ctx->pair_bev) {
			struct evbuffer *in = bufferevent_get_input(ctx->pair_bev);
			if (evbuffer_get_length(in) > 0) {
				evbuffer_add_buffer(bufferevent_get_output(bev), in);
			}
		}
		return;
	}

	if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		if (ctx->pair_bev) {
			struct evbuffer *in = bufferevent_get_input(bev);
			if (evbuffer_get_length(in) > 0)
				evbuffer_add_buffer(bufferevent_get_output(ctx->pair_bev), in);
		}
		http_proxy_close(ctx);
		if (ctx->client && ctx->client->stream_id) {
			del_proxy_client_by_stream_id(ctx->client->stream_id);
		}
	}
}

static int parse_host_port(const char *hp, char *host, size_t hcap, int *port, int def_port)
{
	if (!hp || !*hp) return -1;
	*port = def_port;
	if (hp[0] == '[') {
		const char *rb = strchr(hp, ']');
		if (!rb) return -1;
		size_t len = (size_t)(rb - hp - 1);
		if (len >= hcap) len = hcap - 1;
		memcpy(host, hp + 1, len);
		host[len] = '\0';
		if (rb[1] == ':') *port = atoi(rb + 2);
		return 0;
	}
	const char *colon = strchr(hp, ':');
	if (colon) {
		size_t len = (size_t)(colon - hp);
		if (len >= hcap) len = hcap - 1;
		memcpy(host, hp, len);
		host[len] = '\0';
		*port = atoi(colon + 1);
	} else {
		snprintf(host, hcap, "%s", hp);
	}
	return (*host && *port > 0) ? 0 : -1;
}

static void hp_pair_read_cb(struct bufferevent *bev, void *arg)
{
	struct std_plugin_ctx *ctx = (struct std_plugin_ctx *)arg;
	if (!ctx || !ctx->client || !ctx->client->ps) return;

	struct evbuffer *in = bufferevent_get_input(bev);
	if (ctx->headers_done) {
		if (ctx->remote_bev) {
			evbuffer_add_buffer(bufferevent_get_output(ctx->remote_bev), in);
		}
		return;
	}

	struct evbuffer_ptr eoh = evbuffer_search(in, "\r\n\r\n", 4, NULL);
	if (eoh.pos < 0) {
		if (evbuffer_get_length(in) > 32768) {
			http_proxy_close(ctx);
		}
		return;
	}

	size_t hdr_len = (size_t)eoh.pos + 4;
	char *hdr = malloc(hdr_len + 1);
	if (!hdr) return;
	evbuffer_remove(in, hdr, hdr_len);
	hdr[hdr_len] = '\0';

	struct proxy_service *ps = ctx->client->ps;
	if (!check_basic_auth(hdr, hdr + hdr_len, "Proxy-Authorization",
	                      ps->plugin_user, ps->plugin_pwd)) {
		static const char unauth[] =
			"HTTP/1.1 407 Proxy Authentication Required\r\n"
			"Proxy-Authenticate: Basic realm=\"frp\"\r\n"
			"Content-Length: 0\r\nConnection: close\r\n\r\n";
		bufferevent_write(bev, unauth, sizeof(unauth) - 1);
		free(hdr);
		ctx->headers_done = 1;
		return;
	}

	char method[32] = {0}, target[1024] = {0}, version[32] = {0};
	const char *eol = strstr(hdr, "\r\n");
	if (!eol || sscanf(hdr, "%31s %1023s %31s", method, target, version) != 3) {
		static const char bad[] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
		bufferevent_write(bev, bad, sizeof(bad) - 1);
		free(hdr);
		return;
	}

	char host[256] = {0};
	int port = 80;
	const char *path = target;

	if (strcasecmp(method, "CONNECT") == 0) {
		ctx->is_connect = 1;
		if (parse_host_port(target, host, sizeof(host), &port, 443) < 0) {
			free(hdr);
			return;
		}
	} else {
		ctx->is_connect = 0;
		if (strncasecmp(target, "http://", 7) == 0) {
			const char *hp = target + 7;
			const char *slash = strchr(hp, '/');
			char hpbuf[300];
			size_t hplen = slash ? (size_t)(slash - hp) : strlen(hp);
			if (hplen >= sizeof(hpbuf)) hplen = sizeof(hpbuf) - 1;
			memcpy(hpbuf, hp, hplen);
			hpbuf[hplen] = '\0';
			parse_host_port(hpbuf, host, sizeof(host), &port, 80);
			path = slash ? slash : "/";
		} else {
			/* Look for Host: header */
			const char *p = eol + 2;
			while (p < hdr + hdr_len) {
				const char *nl = strstr(p, "\r\n");
				if (!nl || nl == p) break;
				if (strncasecmp(p, "Host:", 5) == 0) {
					const char *v = p + 5;
					while (v < nl && (*v == ' ' || *v == '\t')) v++;
					char hpbuf[300];
					size_t l = (size_t)(nl - v);
					if (l >= sizeof(hpbuf)) l = sizeof(hpbuf) - 1;
					memcpy(hpbuf, v, l);
					hpbuf[l] = '\0';
					parse_host_port(hpbuf, host, sizeof(host), &port, 80);
					break;
				}
				p = nl + 2;
			}
		}
	}

	if (!*host) {
		static const char bad[] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
		bufferevent_write(bev, bad, sizeof(bad) - 1);
		free(hdr);
		return;
	}

	struct control *ctl = get_main_control();
	struct bufferevent *rbev = bufferevent_socket_new(ctx->client->base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (!rbev) {
		free(hdr);
		return;
	}
	ctx->remote_bev = rbev;
	ctx->headers_done = 1;
	bufferevent_setcb(rbev, hp_remote_read_cb, NULL, hp_remote_event_cb, ctx);
	bufferevent_enable(rbev, EV_READ | EV_WRITE);

	if (!ctx->is_connect) {
		/* Reconstruct request line with origin-form path and strip Proxy-* headers */
		struct evbuffer *out = bufferevent_get_output(rbev);
		evbuffer_add_printf(out, "%s %s %s\r\n", method, path, version);
		const char *p = eol + 2;
		while (p < hdr + hdr_len) {
			const char *nl = strstr(p, "\r\n");
			if (!nl) break;
			if (nl == p) {
				evbuffer_add(out, "\r\n", 2);
				break;
			}
			if (strncasecmp(p, "Proxy-Connection:", 17) != 0 &&
			    strncasecmp(p, "Proxy-Authorization:", 20) != 0) {
				evbuffer_add(out, p, (size_t)(nl - p) + 2);
			}
			p = nl + 2;
		}
	}
	free(hdr);

	struct in_addr addr4;
	if (inet_pton(AF_INET, host, &addr4) == 1) {
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr = addr4;
		sin.sin_port = htons((uint16_t)port);
		bufferevent_socket_connect(rbev, (struct sockaddr *)&sin, sizeof(sin));
	} else if (ctl && ctl->dnsbase) {
		bufferevent_socket_connect_hostname(rbev, ctl->dnsbase, AF_INET, host, port);
	} else {
		http_proxy_close(ctx);
	}
}

/* ---------------- static_file plugin ---------------- */

static const char *guess_mime_type(const char *path)
{
	const char *ext = strrchr(path, '.');
	if (!ext) return "application/octet-stream";
	if (strcasecmp(ext, ".html") == 0 || strcasecmp(ext, ".htm") == 0) return "text/html; charset=utf-8";
	if (strcasecmp(ext, ".txt") == 0 || strcasecmp(ext, ".log") == 0) return "text/plain; charset=utf-8";
	if (strcasecmp(ext, ".css") == 0) return "text/css";
	if (strcasecmp(ext, ".js") == 0) return "application/javascript";
	if (strcasecmp(ext, ".json") == 0) return "application/json";
	if (strcasecmp(ext, ".png") == 0) return "image/png";
	if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0) return "image/jpeg";
	if (strcasecmp(ext, ".svg") == 0) return "image/svg+xml";
	return "application/octet-stream";
}

static void sf_pair_read_cb(struct bufferevent *bev, void *arg)
{
	struct std_plugin_ctx *ctx = (struct std_plugin_ctx *)arg;
	if (!ctx || !ctx->client || !ctx->client->ps) return;

	struct evbuffer *in = bufferevent_get_input(bev);
	struct evbuffer_ptr eoh = evbuffer_search(in, "\r\n\r\n", 4, NULL);
	if (eoh.pos < 0) return;

	size_t hdr_len = (size_t)eoh.pos + 4;
	char *hdr = malloc(hdr_len + 1);
	if (!hdr) return;
	evbuffer_remove(in, hdr, hdr_len);
	hdr[hdr_len] = '\0';

	struct proxy_service *ps = ctx->client->ps;
	if (!check_basic_auth(hdr, hdr + hdr_len, "Authorization",
	                      ps->plugin_user, ps->plugin_pwd)) {
		static const char unauth[] =
			"HTTP/1.1 401 Unauthorized\r\n"
			"WWW-Authenticate: Basic realm=\"frp\"\r\n"
			"Content-Length: 0\r\nConnection: close\r\n\r\n";
		bufferevent_write(bev, unauth, sizeof(unauth) - 1);
		free(hdr);
		return;
	}

	char method[16] = {0}, req_path[1024] = {0};
	if (sscanf(hdr, "%15s %1023s", method, req_path) != 2) {
		free(hdr);
		return;
	}
	free(hdr);

	char *q = strchr(req_path, '?');
	if (q) *q = '\0';

	const char *rel = req_path;
	if (ps->plugin_strip_prefix && *ps->plugin_strip_prefix) {
		size_t plen = strlen(ps->plugin_strip_prefix);
		if (strncmp(rel, ps->plugin_strip_prefix, plen) == 0) {
			rel += plen;
		}
	}
	while (*rel == '/') rel++;

	char root_real[PATH_MAX];
	if (!ps->s_root_dir || !realpath(ps->s_root_dir, root_real)) {
		static const char nf[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
		bufferevent_write(bev, nf, sizeof(nf) - 1);
		return;
	}

	char candidate[PATH_MAX + 1028];
	snprintf(candidate, sizeof(candidate), "%s/%s", root_real, rel);
	char target_real[PATH_MAX];
	if (!realpath(candidate, target_real) ||
	    strncmp(target_real, root_real, strlen(root_real)) != 0) {
		static const char nf[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
		bufferevent_write(bev, nf, sizeof(nf) - 1);
		return;
	}

	struct stat st;
	if (stat(target_real, &st) != 0) {
		static const char nf[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
		bufferevent_write(bev, nf, sizeof(nf) - 1);
		return;
	}

	if (S_ISDIR(st.st_mode)) {
		char idx[PATH_MAX + 32];
		snprintf(idx, sizeof(idx), "%s/index.html", target_real);
		struct stat ist;
		if (strlen(idx) < PATH_MAX && stat(idx, &ist) == 0 && S_ISREG(ist.st_mode)) {
			memcpy(target_real, idx, strlen(idx) + 1);
			st = ist;
		} else {
			struct evbuffer *body = evbuffer_new();
			evbuffer_add_printf(body, "<html><body><h3>Index of /%s</h3><ul>", rel);
			DIR *d = opendir(target_real);
			if (d) {
				struct dirent *ent;
				while ((ent = readdir(d)) != NULL) {
					if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
						continue;
					evbuffer_add_printf(body, "<li><a href=\"%s\">%s</a></li>",
					                    ent->d_name, ent->d_name);
				}
				closedir(d);
			}
			evbuffer_add_printf(body, "</ul></body></html>");
			size_t blen = evbuffer_get_length(body);
			struct evbuffer *out = bufferevent_get_output(bev);
			evbuffer_add_printf(out,
				"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
				"Content-Length: %zu\r\nConnection: close\r\n\r\n", blen);
			if (strcasecmp(method, "HEAD") != 0) {
				evbuffer_add_buffer(out, body);
			}
			evbuffer_free(body);
			return;
		}
	}

	int ffd = open(target_real, O_RDONLY);
	if (ffd < 0) {
		static const char nf[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nForbidden";
		bufferevent_write(bev, nf, sizeof(nf) - 1);
		return;
	}

	struct evbuffer *out = bufferevent_get_output(bev);
	evbuffer_add_printf(out,
		"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %lld\r\n"
		"Connection: close\r\n\r\n",
		guess_mime_type(target_real), (long long)st.st_size);
	if (strcasecmp(method, "HEAD") != 0 && st.st_size > 0) {
		evbuffer_add_file(out, ffd, 0, st.st_size);
	} else {
		close(ffd);
	}
}

int std_plugin_setup(struct proxy_client *client)
{
	if (!client || !client->ps || !client->base) return -1;

	struct bufferevent *pair[2] = {NULL, NULL};
	if (bufferevent_pair_new(client->base, BEV_OPT_CLOSE_ON_FREE, pair) != 0) {
		debug(LOG_ERR, "std_plugin: bufferevent_pair_new failed");
		return -1;
	}

	struct std_plugin_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		bufferevent_free(pair[0]);
		bufferevent_free(pair[1]);
		return -1;
	}
	ctx->client = client;
	ctx->pair_bev = pair[1];
	client->local_proxy_bev = pair[0];
	client->visitor_ctx = ctx; /* freed in std_plugin_cleanup */

	if (strcmp(client->ps->plugin, "http_proxy") == 0) {
		bufferevent_setcb(pair[1], hp_pair_read_cb, NULL, NULL, ctx);
	} else {
		bufferevent_setcb(pair[1], sf_pair_read_cb, NULL, NULL, ctx);
	}
	bufferevent_enable(pair[1], EV_READ | EV_WRITE);
	return 0;
}

void std_plugin_cleanup(struct proxy_client *client)
{
	if (!client || !client->visitor_ctx) return;
	struct std_plugin_ctx *ctx = (struct std_plugin_ctx *)client->visitor_ctx;
	ctx->client = NULL;
	if (ctx->remote_bev) {
		bufferevent_free(ctx->remote_bev);
		ctx->remote_bev = NULL;
	}
	if (ctx->pair_bev) {
		bufferevent_free(ctx->pair_bev);
		ctx->pair_bev = NULL;
	}
	free(ctx);
	client->visitor_ctx = NULL;
}
