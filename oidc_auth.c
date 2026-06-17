// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * OIDC authentication for xfrpc.
 * Implements OAuth2 client_credentials grant to obtain access tokens.
 * Compatible with frp's auth.oidc.* configuration.
 *
 * Uses raw HTTP/HTTPS POST via OpenSSL + sockets (no external HTTP library).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <json-c/json.h>

#include "oidc_auth.h"
#include "debug.h"

#define OIDC_RESPONSE_MAX 8192
#define OIDC_CONNECT_TIMEOUT 10

/* ---- URL parsing helper ---- */

struct parsed_url {
	char host[256];
	int port;
	char path[512];
	int is_https;
};

static int parse_url(const char *url, struct parsed_url *out)
{
	if (!url || !out) return -1;
	memset(out, 0, sizeof(*out));

	const char *p = url;
	if (strncmp(p, "https://", 8) == 0) {
		out->is_https = 1;
		out->port = 443;
		p += 8;
	} else if (strncmp(p, "http://", 7) == 0) {
		out->is_https = 0;
		out->port = 80;
		p += 7;
	} else {
		return -1;
	}

	/* Parse host:port/path */
	const char *slash = strchr(p, '/');
	const char *colon = strchr(p, ':');

	if (colon && (!slash || colon < slash)) {
		int host_len = colon - p;
		if (host_len >= (int)sizeof(out->host)) return -1;
		memcpy(out->host, p, host_len);
		out->host[host_len] = '\0';
		out->port = atoi(colon + 1);
	} else {
		int host_len = slash ? (int)(slash - p) : (int)strlen(p);
		if (host_len >= (int)sizeof(out->host)) return -1;
		memcpy(out->host, p, host_len);
		out->host[host_len] = '\0';
	}

	if (slash) {
		snprintf(out->path, sizeof(out->path), "%s", slash);
	} else {
		strcpy(out->path, "/");
	}

	return 0;
}

/* ---- TCP connection ---- */

static int tcp_connect(const char *host, int port)
{
	struct addrinfo hints = {0}, *res = NULL;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char port_str[8];
	snprintf(port_str, sizeof(port_str), "%d", port);

	if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
		debug(LOG_ERR, "OIDC: DNS lookup failed for %s", host);
		return -1;
	}

	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0) {
		freeaddrinfo(res);
		return -1;
	}

	/* Set connect timeout */
	struct timeval tv = {.tv_sec = OIDC_CONNECT_TIMEOUT, .tv_usec = 0};
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
		debug(LOG_ERR, "OIDC: connect to %s:%d failed: %s", host, port, strerror(errno));
		close(fd);
		freeaddrinfo(res);
		return -1;
	}

	freeaddrinfo(res);
	return fd;
}

/* ---- Send all bytes ---- */

static int send_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	while (len > 0) {
		ssize_t n = send(fd, p, len, 0);
		if (n <= 0) return -1;
		p += n;
		len -= n;
	}
	return 0;
}

/* ---- SSL send/recv helpers ---- */

static int ssl_send_all(SSL *ssl, const void *buf, size_t len)
{
	const char *p = buf;
	while (len > 0) {
		int n = SSL_write(ssl, p, len);
		if (n <= 0) return -1;
		p += n;
		len -= n;
	}
	return 0;
}

static int ssl_recv_all(SSL *ssl, char *buf, size_t buf_size, size_t *out_len)
{
	*out_len = 0;
	while (*out_len < buf_size - 1) {
		int n = SSL_read(ssl, buf + *out_len, buf_size - 1 - *out_len);
		if (n <= 0) break;
		*out_len += n;
	}
	buf[*out_len] = '\0';
	return (*out_len > 0) ? 0 : -1;
}

/* ---- Build POST body ---- */

static char *build_post_body(const char *client_id, const char *client_secret,
                             const char *audience, const char *scope)
{
	/* URL-encode a simple string (only encode spaces and special chars) */
	#define URLENCODE_MAX 1024
	char enc_id[URLENCODE_MAX], enc_secret[URLENCODE_MAX];
	char enc_aud[URLENCODE_MAX], enc_scope[URLENCODE_MAX];

	/* Simple percent-encode for common characters */
	auto void urlencode(const char *src, char *dst, size_t dst_size) {
		const char *hex = "0123456789ABCDEF";
		size_t pos = 0;
		for (; *src && pos < dst_size - 4; src++) {
			unsigned char c = (unsigned char)*src;
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
				dst[pos++] = c;
			} else if (c == ' ') {
				dst[pos++] = '+';
			} else {
				dst[pos++] = '%';
				dst[pos++] = hex[c >> 4];
				dst[pos++] = hex[c & 0xF];
			}
		}
		dst[pos] = '\0';
	}

	urlencode(client_id, enc_id, sizeof(enc_id));
	urlencode(client_secret, enc_secret, sizeof(enc_secret));

	char *body = malloc(2048);
	if (!body) return NULL;

	int len = snprintf(body, 2048,
		"grant_type=client_credentials"
		"&client_id=%s"
		"&client_secret=%s",
		enc_id, enc_secret);

	if (audience && *audience) {
		urlencode(audience, enc_aud, sizeof(enc_aud));
		len += snprintf(body + len, 2048 - len, "&audience=%s", enc_aud);
	}
	if (scope && *scope) {
		urlencode(scope, enc_scope, sizeof(enc_scope));
		len += snprintf(body + len, 2048 - len, "&scope=%s", enc_scope);
	}

	return body;
}

/* ---- Extract access_token from JSON response ---- */

static char *extract_access_token(const char *response)
{
	/* Find the JSON body (after \r\n\r\n) */
	const char *body = strstr(response, "\r\n\r\n");
	if (!body) body = strstr(response, "\n\n");
	if (!body) return NULL;
	body += (body[1] == '\n') ? 2 : 4;

	struct json_object *root = json_tokener_parse(body);
	if (!root) {
		debug(LOG_ERR, "OIDC: failed to parse token response JSON");
		return NULL;
	}

	struct json_object *token_obj = NULL;
	if (!json_object_object_get_ex(root, "access_token", &token_obj)) {
		debug(LOG_ERR, "OIDC: no access_token in response");
		json_object_put(root);
		return NULL;
	}

	const char *token_str = json_object_get_string(token_obj);
	char *result = token_str ? strdup(token_str) : NULL;
	json_object_put(root);

	if (result) {
		debug(LOG_INFO, "OIDC: got access token (len=%zu)", strlen(result));
	} else {
		debug(LOG_ERR, "OIDC: failed to extract access token");
	}
	return result;
}

/* ---- Main: fetch OIDC token ---- */

char *oidc_fetch_token(const char *token_endpoint_url,
                       const char *client_id,
                       const char *client_secret,
                       const char *audience,
                       const char *scope,
                       const char *trusted_ca_file,
                       int insecure_skip_verify)
{
	if (!token_endpoint_url || !client_id || !client_secret) {
		debug(LOG_ERR, "OIDC: missing required parameters");
		return NULL;
	}

	struct parsed_url url;
	if (parse_url(token_endpoint_url, &url) < 0) {
		debug(LOG_ERR, "OIDC: invalid token endpoint URL: %s", token_endpoint_url);
		return NULL;
	}

	debug(LOG_INFO, "OIDC: fetching token from %s (TLS=%d)", url.host, url.is_https);

	/* Build HTTP request */
	char *post_body = build_post_body(client_id, client_secret, audience, scope);
	if (!post_body) return NULL;

	char request[4096];
	int req_len = snprintf(request, sizeof(request),
		"POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",
		url.path, url.host, strlen(post_body), post_body);
	free(post_body);

	/* Connect */
	int fd = tcp_connect(url.host, url.port);
	if (fd < 0) return NULL;

	SSL *ssl = NULL;
	SSL_CTX *ssl_ctx = NULL;

	if (url.is_https) {
		ssl_ctx = SSL_CTX_new(TLS_client_method());
		if (!ssl_ctx) {
			close(fd);
			return NULL;
		}
		if (insecure_skip_verify) {
			SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
		} else if (trusted_ca_file) {
			SSL_CTX_load_verify_locations(ssl_ctx, trusted_ca_file, NULL);
			SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
		}
		ssl = SSL_new(ssl_ctx);
		SSL_set_fd(ssl, fd);
		SSL_set_tlsext_host_name(ssl, url.host);
		if (SSL_connect(ssl) != 1) {
			debug(LOG_ERR, "OIDC: TLS handshake failed");
			SSL_free(ssl);
			SSL_CTX_free(ssl_ctx);
			close(fd);
			return NULL;
		}
	}

	/* Send request */
	int ret;
	if (ssl) {
		ret = ssl_send_all(ssl, request, req_len);
	} else {
		ret = send_all(fd, request, req_len);
	}
	if (ret < 0) {
		debug(LOG_ERR, "OIDC: failed to send request");
		if (ssl) { SSL_free(ssl); SSL_CTX_free(ssl_ctx); }
		close(fd);
		return NULL;
	}

	/* Read response */
	char *response = malloc(OIDC_RESPONSE_MAX);
	if (!response) {
		if (ssl) { SSL_free(ssl); SSL_CTX_free(ssl_ctx); }
		close(fd);
		return NULL;
	}

	size_t resp_len = 0;
	if (ssl) {
		ret = ssl_recv_all(ssl, response, OIDC_RESPONSE_MAX, &resp_len);
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
	} else {
		/* Read until connection closes */
		while (resp_len < OIDC_RESPONSE_MAX - 1) {
			ssize_t n = recv(fd, response + resp_len, OIDC_RESPONSE_MAX - 1 - resp_len, 0);
			if (n <= 0) break;
			resp_len += n;
		}
		response[resp_len] = '\0';
		ret = (resp_len > 0) ? 0 : -1;
	}
	close(fd);

	if (ret < 0) {
		debug(LOG_ERR, "OIDC: failed to read response");
		free(response);
		return NULL;
	}

	/* Extract access_token */
	char *token = extract_access_token(response);
	free(response);
	return token;
}
