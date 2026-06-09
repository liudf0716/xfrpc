// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <json-c/json.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/event.h>

#include "debug.h"
#include "visitor.h"
#include "config.h"
#include "control.h"
#include "msg.h"
#include "login.h"
#include "tls.h"
#include "tcpmux.h"
#include "xtcp_visitor.h"

#include "common.h"
#include "uthash.h"

/* ---- global state ---- */

static struct visitor_conf *all_visitor_confs = NULL;
static struct visitor_instance *all_visitors = NULL;

/* ---- visitor conf management ---- */

struct visitor_conf *get_all_visitor_confs(void)
{
	return all_visitor_confs;
}

void free_all_visitor_confs(void)
{
	struct visitor_conf *vc, *tmp;
	HASH_ITER(hh, all_visitor_confs, vc, tmp) {
		HASH_DEL(all_visitor_confs, vc);
		SAFE_FREE(vc->visitor_name);
		SAFE_FREE(vc->visitor_type);
		SAFE_FREE(vc->server_name);
		SAFE_FREE(vc->secret_key);
		SAFE_FREE(vc->bind_addr);
		SAFE_FREE(vc);
	}
	all_visitor_confs = NULL;
}

/* ---- INI section parser ---- */

int parse_visitor_section(const char *section_name, const char *key, const char *value)
{
	if (!section_name || !key || !value)
		return 0;

	const char *colon = strchr(section_name, ':');
	if (!colon)
		return 0;

	const char *visitor_marker = strstr(section_name, "visitor");
	if (!visitor_marker || visitor_marker >= colon)
		return 0;

	const char *vname = colon + 1;
	if (*vname == '\0')
		return 0;

	struct visitor_conf *vc = NULL;
	HASH_FIND_STR(all_visitor_confs, vname, vc);
	if (!vc) {
		vc = calloc(1, sizeof(struct visitor_conf));
		assert(vc);
		vc->visitor_name = strdup(vname);
		vc->bind_addr = strdup("127.0.0.1");
		vc->bind_port = 0;
		assert(vc->visitor_name);
		assert(vc->bind_addr);
		HASH_ADD_KEYPTR(hh, all_visitor_confs, vc->visitor_name,
			strlen(vc->visitor_name), vc);
		debug(LOG_DEBUG, "Created visitor conf: %s", vname);
	}

	if (strcmp(key, "type") == 0) {
		SAFE_FREE(vc->visitor_type);
		vc->visitor_type = strdup(value);
	} else if (strcmp(key, "server_name") == 0) {
		SAFE_FREE(vc->server_name);
		vc->server_name = strdup(value);
	} else if (strcmp(key, "sk") == 0 || strcmp(key, "secret_key") == 0) {
		SAFE_FREE(vc->secret_key);
		vc->secret_key = strdup(value);
	} else if (strcmp(key, "bind_addr") == 0) {
		SAFE_FREE(vc->bind_addr);
		vc->bind_addr = strdup(value);
	} else if (strcmp(key, "bind_port") == 0) {
		vc->bind_port = atoi(value);
	} else if (strcmp(key, "use_encryption") == 0) {
		vc->use_encryption = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
	} else if (strcmp(key, "use_compression") == 0) {
		vc->use_compression = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
	}

	return 1;
}

/* ---- validation ---- */

static int validate_visitor_confs(void)
{
	struct visitor_conf *vc, *tmp;
	HASH_ITER(hh, all_visitor_confs, vc, tmp) {
		if (!vc->visitor_type) {
			debug(LOG_ERR, "Visitor [%s]: type not set", vc->visitor_name);
			return 0;
		}
		if (!vc->server_name) {
			debug(LOG_ERR, "Visitor [%s]: server_name not set", vc->visitor_name);
			return 0;
		}
		if (!vc->secret_key) {
			debug(LOG_ERR, "Visitor [%s]: sk (secret_key) not set", vc->visitor_name);
			return 0;
		}
		if (vc->bind_port <= 0) {
			debug(LOG_ERR, "Visitor [%s]: bind_port not set or invalid", vc->visitor_name);
			return 0;
		}
		debug(LOG_DEBUG, "Visitor [%s]: type=%s server=%s bind=%s:%d",
			vc->visitor_name, vc->visitor_type, vc->server_name,
			vc->bind_addr, vc->bind_port);
	}
	return 1;
}

/* ---- visitor session state machine ---- */

enum visitor_sess_state {
	VSESS_CONNECTING,     /* Waiting for frps connection */
	VSESS_SENDING,        /* Sending NewVisitorConn */
	VSESS_WAIT_RESP,      /* Waiting for NewVisitorConnResp */
	VSESS_TUNNEL,         /* Tunneling data */
	VSESS_DONE,
};

struct visitor_session {
	struct visitor_conf     *conf;
	struct bufferevent      *user_bev;   /* local user connection */
	struct bufferevent      *frps_bev;   /* connection to frps (legacy, unused in tmux mode) */
	struct proxy_client     *client;     /* tmux stream proxy client */
	enum visitor_sess_state  state;
	int                      tls_done;   /* TLS already wrapped */
};

static void visitor_session_free(struct visitor_session *sess)
{
	if (!sess) return;
	if (sess->user_bev) bufferevent_free(sess->user_bev);
	if (sess->frps_bev) bufferevent_free(sess->frps_bev);
	free(sess);
}

/* ---- tunnel forwarding callbacks ---- */

static void tunnel_user_recv_cb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *dst = (struct bufferevent *)ctx;
	if (!dst) return;
	struct evbuffer *src = bufferevent_get_input(bev);
	struct evbuffer *out = bufferevent_get_output(dst);
	evbuffer_add_buffer(out, src);
}

static void tunnel_frps_recv_cb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *dst = (struct bufferevent *)ctx;
	if (!dst) return;
	struct evbuffer *src = bufferevent_get_input(bev);
	struct evbuffer *out = bufferevent_get_output(dst);
	evbuffer_add_buffer(out, src);
}

static void tunnel_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	struct visitor_session *sess = (struct visitor_session *)ctx;
	if (!sess) return;

	if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		debug(LOG_DEBUG, "Visitor [%s]: tunnel side closed",
			sess->conf->visitor_name);
		visitor_session_free(sess);
	}
}

/* ---- frps response handling ---- */

/**
 * @brief Parse NewVisitorConnResp JSON and check for errors.
 * Returns 0 on success, -1 on error.
 */
static int parse_visitor_conn_resp(const char *json_str)
{
	if (!json_str) return -1;

	struct json_object *jobj = json_tokener_parse(json_str);
	if (!jobj) return -1;

	struct json_object *jerr = NULL;
	if (json_object_object_get_ex(jobj, "error", &jerr)) {
		const char *err = json_object_get_string(jerr);
		if (err && strlen(err) > 0) {
			debug(LOG_ERR, "NewVisitorConnResp error: %s", err);
			json_object_put(jobj);
			return -1;
		}
	}

	json_object_put(jobj);
	return 0;
}

/**
 * @brief Read callback for the frps connection during handshake.
 *
 * Reads the NewVisitorConnResp from frps. On success, transitions to
 * bidirectional tunnel mode. On failure, closes the session.
 */
static void visitor_frps_recv_cb(struct bufferevent *bev, void *ctx)
{
	struct visitor_session *sess = (struct visitor_session *)ctx;
	if (!sess) return;

	struct evbuffer *input = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(input);
	if (len == 0) return;

	if (sess->state == VSESS_WAIT_RESP) {
		/* Read framed response: [type:1][length:8][data:N] */
		if (len < sizeof(struct msg_hdr)) return;

		struct msg_hdr resp_hdr;
		memcpy(&resp_hdr, evbuffer_pullup(input, sizeof(struct msg_hdr)), sizeof(struct msg_hdr));

		uint64_t data_len = msg_ntoh(resp_hdr.length);
		size_t frame_total = sizeof(struct msg_hdr) + (size_t)data_len;

		if (len < frame_total) return;

		/* Pull the full frame */
		char *frame = malloc(frame_total);
		if (!frame) {
			visitor_session_free(sess);
			return;
		}
		evbuffer_remove(input, frame, frame_total);

		/* Parse response JSON */
		char *resp_json = frame + sizeof(struct msg_hdr);
		int rc = parse_visitor_conn_resp(resp_json);
		free(frame);

		if (rc != 0) {
			debug(LOG_ERR, "Visitor [%s]: frps rejected visitor connection",
				sess->conf->visitor_name);
			visitor_session_free(sess);
			return;
		}

		debug(LOG_INFO, "Visitor [%s]: handshake OK, entering tunnel mode",
			sess->conf->visitor_name);

		/* Transition to tunnel mode */
		sess->state = VSESS_TUNNEL;

		/* Now set up bidirectional forwarding:
		 *   user → frps: tunnel_user_recv_cb
		 *   frps → user: tunnel_frps_recv_cb
		 */
		bufferevent_setcb(sess->user_bev, tunnel_user_recv_cb, NULL,
			tunnel_event_cb, sess);
		bufferevent_setcb(sess->frps_bev, tunnel_frps_recv_cb, NULL,
			tunnel_event_cb, sess);
		bufferevent_enable(sess->user_bev, EV_READ | EV_WRITE);
		bufferevent_enable(sess->frps_bev, EV_READ | EV_WRITE);

		/* If there's any remaining data in frps input, forward it to user */
		size_t remain = evbuffer_get_length(bufferevent_get_input(sess->frps_bev));
		if (remain > 0) {
			struct evbuffer *src = bufferevent_get_input(sess->frps_bev);
			struct evbuffer *dst = bufferevent_get_output(sess->user_bev);
			evbuffer_add_buffer(dst, src);
		}
		return;
	}

	/* In TUNNEL mode, this callback shouldn't be called (replaced above) */
}

/* ---- frps connection event callback (non-mux mode) ---- */

static void visitor_frps_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	struct visitor_session *sess = (struct visitor_session *)ctx;
	if (!sess) return;

	if (what & BEV_EVENT_CONNECTED) {
		debug(LOG_DEBUG, "Visitor [%s]: connected to frps", sess->conf->visitor_name);

		/* Wrap with TLS if enabled and not already done */
		struct common_conf *c_conf = get_common_config();
		if (c_conf && c_conf->tls_enable && !sess->tls_done) {
			sess->tls_done = 1;
			struct event_base *base = bufferevent_get_base(bev);
			struct bufferevent *ssl_bev = tls_wrap_bev(base, bev);
			if (!ssl_bev) {
				debug(LOG_ERR, "Visitor [%s]: TLS wrap failed",
					sess->conf->visitor_name);
				visitor_session_free(sess);
				return;
			}
			bufferevent_setcb(ssl_bev, NULL, NULL,
				visitor_frps_event_cb, sess);
			bufferevent_enable(ssl_bev, EV_READ | EV_WRITE);
			bufferevent_socket_connect(ssl_bev, NULL, 0);
			return;
		}

		/* Send the pre-built NewVisitorConn msg_hdr */
		struct msg_hdr *hdr = (struct msg_hdr *)sess->frps_bev;
		if (hdr) {
			size_t total = sizeof(struct msg_hdr) + msg_ntoh(hdr->length);
			debug(LOG_DEBUG, "Visitor [%s]: sending NewVisitorConn for proxy '%s'",
				sess->conf->visitor_name, sess->conf->server_name);
			bufferevent_write(bev, hdr, total);
			free(hdr);
			sess->frps_bev = bev; /* now store the real connection bev */
		}

		/* Wait for NewVisitorConnResp */
		sess->state = VSESS_WAIT_RESP;
		bufferevent_setcb(bev, visitor_frps_recv_cb, NULL,
			visitor_frps_event_cb, sess);
		bufferevent_enable(bev, EV_READ | EV_WRITE);

	} else if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		debug(LOG_ERR, "Visitor [%s]: frps connection error: %s",
			sess->conf->visitor_name, strerror(errno));
		visitor_session_free(sess);
	}
}

/* ---- user data forwarding: local user → tmux stream ---- */

static void visitor_user_recv_cb(struct bufferevent *bev, void *ctx)
{
	struct visitor_session *sess = (struct visitor_session *)ctx;
	if (!sess || !sess->client) return;

	struct evbuffer *input = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(input);
	if (len == 0) return;

	/* Forward data from local user through the tmux stream to frps */
	struct evbuffer *tmp = evbuffer_new();
	if (!tmp) return;
	evbuffer_add_buffer(tmp, input);
	if (tmux_stream_write(sess->client->ctl_bev, tmp, &sess->client->stream) < 0) {
		debug(LOG_ERR, "Visitor [%s]: failed to write user data through tmux",
			sess->conf->visitor_name);
	}
	evbuffer_free(tmp);
}

/* ---- user connection event callback ---- */

static void visitor_user_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	struct visitor_session *sess = (struct visitor_session *)ctx;
	if (!sess) return;

	if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		debug(LOG_DEBUG, "Visitor [%s]: local user disconnected",
			sess->conf->visitor_name);
		if (sess->client) {
			struct proxy_client *pc = sess->client;
			pc->visitor_ctx = NULL; /* Prevent free_proxy_client from freeing sess */
			pc->local_proxy_bev = NULL; /* user_bev freed by visitor_session_free */
			del_proxy_client_by_stream_id(pc->stream_id);
			sess->client = NULL;
		}
		visitor_session_free(sess);
	}
}

/* ---- local listener accept callback ---- */

static void visitor_accept_cb(struct evconnlistener *listener,
	evutil_socket_t fd, struct sockaddr *addr, int socklen, void *ctx)
{
	struct visitor_instance *vi = (struct visitor_instance *)ctx;
	if (!vi || !vi->conf) return;

	debug(LOG_INFO, "Visitor [%s]: new local connection (fd=%d)",
		vi->conf->visitor_name, fd);

	/* Route XTCP visitors to the dedicated XTCP handler */
	if (vi->conf->visitor_type &&
	    strcmp(vi->conf->visitor_type, "xtcp") == 0) {
		struct event_base *base = evconnlistener_get_base(listener);
		struct bufferevent *user_bev = bufferevent_socket_new(base, fd,
			BEV_OPT_CLOSE_ON_FREE);
		if (!user_bev) {
			close(fd);
			return;
		}
		xtcp_visitor_run(base, vi, user_bev);
		return;
	}

	struct event_base *base = evconnlistener_get_base(listener);
	struct common_conf *c_conf = get_common_config();

	/* Create session */
	struct visitor_session *sess = calloc(1, sizeof(struct visitor_session));
	if (!sess) {
		close(fd);
		return;
	}
	sess->conf = vi->conf;
	sess->state = VSESS_CONNECTING;

	/* User bev */
	sess->user_bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!sess->user_bev) {
		free(sess);
		close(fd);
		return;
	}
	bufferevent_setcb(sess->user_bev, NULL, NULL, visitor_user_event_cb, sess);
	bufferevent_enable(sess->user_bev, EV_READ | EV_WRITE);

	/* Use control connection's tmux to send NewVisitorConn (same as frpc) */
	struct proxy_client *client = new_proxy_client();
	if (!client) {
		debug(LOG_ERR, "Visitor [%s]: failed to create proxy client",
			vi->conf->visitor_name);
		visitor_session_free(sess);
		return;
	}

	client->base = base;
	client->ctl_bev = get_main_control()->connect_bev;
	client->local_proxy_bev = NULL; /* Defer binding until handshake OK */
	client->visitor_ctx = sess;
	sess->client = client; /* reverse link for data forwarding */

	if (c_conf->tcp_mux) {
		/* Send WINDOW_UPDATE + NewVisitorConn through tmux stream */
		debug(LOG_DEBUG, "Visitor [%s]: using tmux stream_id=%d",
			vi->conf->visitor_name, client->stream_id);
		send_window_update(client->ctl_bev, &client->stream, 0);

		/* Build NewVisitorConn JSON */
		struct login *lg = get_common_login_config();
		time_t timestamp = time(NULL);
		char *sign_key = get_auth_key(sess->conf->secret_key, &timestamp);
		if (!sign_key) {
			debug(LOG_ERR, "Visitor [%s]: failed to generate sign_key",
				vi->conf->visitor_name);
			free(client);
			visitor_session_free(sess);
			return;
		}

		struct json_object *jreq = json_object_new_object();
		json_object_object_add(jreq, "run_id",
			json_object_new_string(lg->run_id ? lg->run_id : ""));
		json_object_object_add(jreq, "proxy_name",
			json_object_new_string(sess->conf->server_name));
		json_object_object_add(jreq, "sign_key",
			json_object_new_string(sign_key));
		if (sizeof(time_t) == 4) {
			json_object_object_add(jreq, "timestamp",
				json_object_new_int((int32_t)timestamp));
		} else {
			json_object_object_add(jreq, "timestamp",
				json_object_new_int64((int64_t)timestamp));
		}
		json_object_object_add(jreq, "use_encryption",
			json_object_new_boolean(sess->conf->use_encryption));
		json_object_object_add(jreq, "use_compression",
			json_object_new_boolean(sess->conf->use_compression));

		const char *json_str = json_object_to_json_string(jreq);
		int json_len = strlen(json_str);

		debug(LOG_DEBUG, "Visitor [%s]: sending NewVisitorConn for proxy '%s'",
			sess->conf->visitor_name, sess->conf->server_name);

		send_msg_frp_server(client->ctl_bev, TypeNewVisitorConn,
			json_str, json_len, &client->stream);

		json_object_put(jreq);
		SAFE_FREE(sign_key);

		sess->state = VSESS_WAIT_RESP;

		/* Now set up user data forwarding (after client is linked) */
		bufferevent_setcb(sess->user_bev, visitor_user_recv_cb, NULL,
			visitor_user_event_cb, sess);
	} else {
		/* Non-mux mode: create independent TCP connection to frps */
		debug(LOG_DEBUG, "Visitor [%s]: using direct (non-mux) connection",
			vi->conf->visitor_name);

		/* Reuse proxy_client for session tracking */
		free(client);
		sess->client = NULL;

		/* Build NewVisitorConn JSON */
		struct login *lg = get_common_login_config();
		time_t timestamp = time(NULL);
		char *sign_key = get_auth_key(sess->conf->secret_key, &timestamp);
		if (!sign_key) {
			debug(LOG_ERR, "Visitor [%s]: failed to generate sign_key",
				vi->conf->visitor_name);
			visitor_session_free(sess);
			return;
		}

		struct json_object *jreq = json_object_new_object();
		json_object_object_add(jreq, "run_id",
			json_object_new_string(lg->run_id ? lg->run_id : ""));
		json_object_object_add(jreq, "proxy_name",
			json_object_new_string(sess->conf->server_name));
		json_object_object_add(jreq, "sign_key",
			json_object_new_string(sign_key));
		if (sizeof(time_t) == 4) {
			json_object_object_add(jreq, "timestamp",
				json_object_new_int((int32_t)timestamp));
		} else {
			json_object_object_add(jreq, "timestamp",
				json_object_new_int64((int64_t)timestamp));
		}
		json_object_object_add(jreq, "use_encryption",
			json_object_new_boolean(sess->conf->use_encryption));
		json_object_object_add(jreq, "use_compression",
			json_object_new_boolean(sess->conf->use_compression));

		const char *json_str = json_object_to_json_string(jreq);
		int json_len = strlen(json_str);

		/* Pre-build the raw msg_hdr for sending after connection */
		size_t hdr_len = sizeof(struct msg_hdr) + json_len;
		struct msg_hdr *hdr = malloc(hdr_len);
		if (!hdr) {
			json_object_put(jreq);
			SAFE_FREE(sign_key);
			visitor_session_free(sess);
			return;
		}
		hdr->type = TypeNewVisitorConn;
		hdr->length = msg_hton(json_len);
		memcpy(hdr->data, json_str, json_len);

		json_object_put(jreq);
		SAFE_FREE(sign_key);

		/* Store the pre-built message in frps_bev for the event callback */
		sess->frps_bev = (struct bufferevent *)hdr; /* temporarily store msg */
		sess->state = VSESS_CONNECTING;

		/* Create TCP connection to frps */
		struct bufferevent *conn_bev = bufferevent_socket_new(base, -1,
			BEV_OPT_CLOSE_ON_FREE);
		if (!conn_bev) {
			free(hdr);
			visitor_session_free(sess);
			return;
		}

		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(c_conf->server_port);
		inet_pton(AF_INET, c_conf->server_addr, &sin.sin_addr);

		bufferevent_setcb(conn_bev, NULL, NULL,
			visitor_frps_event_cb, sess);
		bufferevent_enable(conn_bev, EV_READ | EV_WRITE);

		if (bufferevent_socket_connect(conn_bev,
				(struct sockaddr *)&sin, sizeof(sin)) < 0) {
			debug(LOG_ERR, "Visitor [%s]: failed to connect to frps",
				vi->conf->visitor_name);
			free(hdr);
			bufferevent_free(conn_bev);
			visitor_session_free(sess);
			return;
		}
	}
}

/* ---- visitor instance init ---- */

static int init_visitor(struct event_base *base, struct visitor_conf *vc)
{
	struct visitor_instance *vi = calloc(1, sizeof(struct visitor_instance));
	if (!vi) return -1;

	vi->conf = vc;
	vi->base = base;

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(vc->bind_port);
	if (inet_pton(AF_INET, vc->bind_addr, &sin.sin_addr) != 1) {
		debug(LOG_ERR, "Visitor [%s]: invalid bind_addr '%s'",
			vc->visitor_name, vc->bind_addr);
		free(vi);
		return -1;
	}

	vi->listener = evconnlistener_new_bind(base, visitor_accept_cb, vi,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 128,
		(struct sockaddr *)&sin, sizeof(sin));

	if (!vi->listener) {
		debug(LOG_ERR, "Visitor [%s]: failed to listen on %s:%d — %s",
			vc->visitor_name, vc->bind_addr, vc->bind_port, strerror(errno));
		free(vi);
		return -1;
	}

	HASH_ADD_KEYPTR(hh, all_visitors, vc->visitor_name,
		strlen(vc->visitor_name), vi);

	debug(LOG_INFO, "Visitor [%s]: listening on %s:%d → proxy '%s'",
		vc->visitor_name, vc->bind_addr, vc->bind_port, vc->server_name);

	return 0;
}

void init_visitors(struct event_base *base)
{
	if (!validate_visitor_confs()) {
		debug(LOG_ERR, "Visitor validation failed, not starting visitors");
		return;
	}

	struct visitor_conf *vc, *tmp;
	HASH_ITER(hh, all_visitor_confs, vc, tmp) {
		init_visitor(base, vc);
	}
}

/* ---- handle NewVisitorConnResp from main control (unused in this design) ---- */

void handle_visitor_conn_resp(const char *resp_json, struct proxy_client *pc)
{
	if (!resp_json || !pc) return;

	struct json_object *jresp = json_tokener_parse(resp_json);
	if (!jresp) {
		debug(LOG_ERR, "Failed to parse NewVisitorConnResp JSON");
		return;
	}

	/* Check for error */
	struct json_object *j_err = NULL;
	const char *err_str = NULL;
	if (json_object_object_get_ex(jresp, "error", &j_err)) {
		err_str = json_object_get_string(j_err);
	}

	struct json_object *j_pname = NULL;
	const char *proxy_name = NULL;
	if (json_object_object_get_ex(jresp, "proxy_name", &j_pname)) {
		proxy_name = json_object_get_string(j_pname);
	}

	if (err_str && strlen(err_str) > 0) {
		debug(LOG_ERR, "Visitor conn resp error for '%s': %s",
			proxy_name ? proxy_name : "?", err_str);
		json_object_put(jresp);
		if (pc->visitor_ctx) {
			struct visitor_session *sess = (struct visitor_session *)pc->visitor_ctx;
			pc->visitor_ctx = NULL; /* Prevent free_proxy_client from double-free */
			sess->client = NULL;
			visitor_session_free(sess);
		}
		del_proxy_client_by_stream_id(pc->stream_id);
		return;
	}

	debug(LOG_DEBUG, "Visitor conn resp OK for proxy '%s'",
		proxy_name ? proxy_name : "?");

	json_object_put(jresp);

	/* Handshake succeeded, link the local user bev to start forwarding data */
	if (pc->visitor_ctx) {
		struct visitor_session *sess = (struct visitor_session *)pc->visitor_ctx;
		pc->local_proxy_bev = sess->user_bev;
		sess->state = VSESS_TUNNEL;
		debug(LOG_INFO, "Visitor [%s]: handshake OK, entering tunnel mode (tmux)",
			sess->conf->visitor_name);
	}
}

/* ---- stop and free all running visitor instances (for hot-reload) ---- */

void free_all_visitor_instances(void)
{
	struct visitor_instance *vi, *tmp;
	HASH_ITER(hh, all_visitors, vi, tmp) {
		if (vi->listener) {
			evconnlistener_free(vi->listener);
		}
		HASH_DEL(all_visitors, vi);
		free(vi);
	}
	all_visitors = NULL;
	debug(LOG_DEBUG, "All visitor instances freed");
}
