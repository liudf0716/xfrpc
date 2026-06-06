// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Health check module for xfrpc proxy services.
 *
 * Supports TCP and HTTP health checks with configurable interval,
 * timeout, and failure threshold. Uses libevent for async I/O.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "health_check.h"
#include "config.h"
#include "debug.h"
#include "uthash.h"

/* ---- per-proxy health check state ---- */

enum hc_state {
	HC_IDLE,         /* Timer-driven, not currently checking */
	HC_CONNECTING,   /* TCP connect in progress */
	HC_SENDING,      /* Sending HTTP request */
	HC_READING,      /* Reading HTTP response */
};

struct health_check_entry {
	char                *proxy_name;
	struct proxy_service *ps;

	/* Config (copied for safety) */
	char                *check_type;   /* "tcp" or "http" */
	char                *check_url;    /* HTTP URL path */
	int                  interval;     /* seconds */
	int                  timeout;      /* seconds */
	int                  max_failed;   /* consecutive failures threshold */

	/* Runtime state */
	int                  failed_count;
	int                  is_healthy;   /* 1 = healthy, 0 = down */
	enum hc_state        state;

	/* libevent objects */
	struct event_base   *base;
	struct event        *timer;
	struct bufferevent  *check_bev;

	/* Callback */
	health_check_cb_t    callback;
	void                *ctx;

	/* Hash handling */
	UT_hash_handle       hh;
};

static struct health_check_entry *all_hc_entries = NULL;

/* ---- forward declarations ---- */
static void hc_timer_cb(evutil_socket_t fd, short what, void *arg);
static void hc_start_check(struct health_check_entry *entry);
static void hc_tcp_event_cb(struct bufferevent *bev, short what, void *arg);
static void hc_http_read_cb(struct bufferevent *bev, void *arg);
static void hc_http_event_cb(struct bufferevent *bev, short what, void *arg);
static void hc_finish_check(struct health_check_entry *entry, int healthy);
static void hc_schedule_next(struct health_check_entry *entry);

/* ---- public API ---- */

void health_check_start_all(struct event_base *base, health_check_cb_t callback, void *ctx)
{
	struct proxy_service *ps, *tmp;
	struct proxy_service *all_ps = get_all_proxy_services();

	if (!all_ps)
		return;

	HASH_ITER(hh, all_ps, ps, tmp) {
		if (!ps->health_check_type)
			continue;

		/* Validate check type */
		if (strcmp(ps->health_check_type, "tcp") != 0 &&
			strcmp(ps->health_check_type, "http") != 0) {
			debug(LOG_ERR, "Proxy [%s]: invalid health_check_type '%s', skipping",
				  ps->proxy_name, ps->health_check_type);
			continue;
		}

		/* Require local_ip and local_port for health checks */
		if (!ps->local_ip || ps->local_port <= 0) {
			debug(LOG_ERR, "Proxy [%s]: health check requires local_ip and local_port",
				  ps->proxy_name);
			continue;
		}

		/* Create entry */
		struct health_check_entry *entry = calloc(1, sizeof(struct health_check_entry));
		if (!entry) {
			debug(LOG_ERR, "Failed to allocate health check entry for %s", ps->proxy_name);
			continue;
		}

		entry->proxy_name = strdup(ps->proxy_name);
		entry->check_type = strdup(ps->health_check_type);
		entry->check_url = strdup(ps->health_check_url ? ps->health_check_url : "/");
		entry->interval = ps->health_check_interval > 0 ? ps->health_check_interval : 10;
		entry->timeout = ps->health_check_timeout > 0 ? ps->health_check_timeout : 3;
		entry->max_failed = ps->health_check_max_failed > 0 ? ps->health_check_max_failed : 1;
		entry->ps = ps;
		entry->base = base;
		entry->callback = callback;
		entry->ctx = ctx;
		entry->is_healthy = 1; /* Assume healthy until proven otherwise */
		entry->state = HC_IDLE;

		/* Create periodic timer */
		entry->timer = evtimer_new(base, hc_timer_cb, entry);
		if (!entry->timer) {
			debug(LOG_ERR, "Failed to create health check timer for %s", ps->proxy_name);
			free(entry->proxy_name);
			free(entry->check_type);
			free(entry->check_url);
			free(entry);
			continue;
		}

		HASH_ADD_KEYPTR(hh, all_hc_entries, entry->proxy_name,
						strlen(entry->proxy_name), entry);

		debug(LOG_INFO, "Health check started for [%s]: type=%s interval=%ds timeout=%ds max_failed=%d",
			  ps->proxy_name, entry->check_type, entry->interval,
			  entry->timeout, entry->max_failed);

		/* Fire the first check immediately (0 delay) */
		struct timeval tv = {0, 0};
		evtimer_add(entry->timer, &tv);
	}
}

void health_check_stop_all(void)
{
	struct health_check_entry *entry, *tmp;

	HASH_ITER(hh, all_hc_entries, entry, tmp) {
		HASH_DEL(all_hc_entries, entry);

		if (entry->timer) {
			evtimer_del(entry->timer);
			event_free(entry->timer);
		}
		if (entry->check_bev) {
			bufferevent_free(entry->check_bev);
		}

		free(entry->proxy_name);
		free(entry->check_type);
		free(entry->check_url);
		free(entry);
	}

	all_hc_entries = NULL;
	debug(LOG_DEBUG, "All health checks stopped");
}

int health_check_is_healthy(const char *proxy_name)
{
	if (!proxy_name)
		return 1;

	struct health_check_entry *entry = NULL;
	HASH_FIND_STR(all_hc_entries, proxy_name, entry);

	if (!entry)
		return 1; /* No health check configured = always healthy */

	return entry->is_healthy;
}

int health_check_count(void)
{
	return HASH_COUNT(all_hc_entries);
}

/* ---- internal: timer fires a health check ---- */

static void hc_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd; (void)what;
	struct health_check_entry *entry = (struct health_check_entry *)arg;

	if (!entry || !entry->ps)
		return;

	/* Check time window (start_time / end_time) */
	struct proxy_service *ps = entry->ps;
	if (ps->start_time != 0 || ps->end_time != 0) {
		time_t now = time(NULL);
		struct tm *t = localtime(&now);
		int hour = t->tm_hour;

		if (ps->start_time <= ps->end_time) {
			/* Same-day window: e.g. 8-18 */
			if (hour < ps->start_time || hour >= ps->end_time) {
				/* Outside window, skip check but schedule next */
				hc_schedule_next(entry);
				return;
			}
		} else {
			/* Overnight window: e.g. 22-6 */
			if (hour < ps->start_time && hour >= ps->end_time) {
				hc_schedule_next(entry);
				return;
			}
		}
	}

	hc_start_check(entry);
}

/* ---- internal: start a TCP or HTTP check ---- */

static void hc_start_check(struct health_check_entry *entry)
{
	if (!entry || !entry->ps)
		return;

	struct proxy_service *ps = entry->ps;

	/* Clean up previous bev if any */
	if (entry->check_bev) {
		bufferevent_free(entry->check_bev);
		entry->check_bev = NULL;
	}

	entry->check_bev = bufferevent_socket_new(entry->base, -1,
											  BEV_OPT_CLOSE_ON_FREE);
	if (!entry->check_bev) {
		debug(LOG_ERR, "Health check [%s]: failed to create bufferevent", entry->proxy_name);
		hc_finish_check(entry, 0);
		return;
	}

	/* Set connection timeout */
	struct timeval tv = {entry->timeout, 0};
	bufferevent_set_timeouts(entry->check_bev, &tv, &tv);

	if (strcmp(entry->check_type, "tcp") == 0) {
		/* TCP check: just connect */
		entry->state = HC_CONNECTING;
		bufferevent_setcb(entry->check_bev, NULL, NULL, hc_tcp_event_cb, entry);
		bufferevent_enable(entry->check_bev, EV_READ | EV_WRITE);

		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(ps->local_port);
		if (inet_pton(AF_INET, ps->local_ip, &sin.sin_addr) != 1) {
			debug(LOG_ERR, "Health check [%s]: invalid local_ip '%s'",
				  entry->proxy_name, ps->local_ip);
			hc_finish_check(entry, 0);
			return;
		}

		if (bufferevent_socket_connect(entry->check_bev,
				(struct sockaddr *)&sin, sizeof(sin)) < 0) {
			debug(LOG_DEBUG, "Health check [%s]: TCP connect failed to start", entry->proxy_name);
			hc_finish_check(entry, 0);
			return;
		}

	} else {
		/* HTTP check: connect, then send GET request */
		entry->state = HC_CONNECTING;
		bufferevent_setcb(entry->check_bev, NULL, NULL, hc_http_event_cb, entry);
		bufferevent_enable(entry->check_bev, EV_READ | EV_WRITE);

		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(ps->local_port);
		if (inet_pton(AF_INET, ps->local_ip, &sin.sin_addr) != 1) {
			debug(LOG_ERR, "Health check [%s]: invalid local_ip '%s'",
				  entry->proxy_name, ps->local_ip);
			hc_finish_check(entry, 0);
			return;
		}

		if (bufferevent_socket_connect(entry->check_bev,
				(struct sockaddr *)&sin, sizeof(sin)) < 0) {
			debug(LOG_DEBUG, "Health check [%s]: HTTP connect failed to start", entry->proxy_name);
			hc_finish_check(entry, 0);
			return;
		}
	}
}

/* ---- internal: TCP check event callback ---- */

static void hc_tcp_event_cb(struct bufferevent *bev, short what, void *arg)
{
	struct health_check_entry *entry = (struct health_check_entry *)arg;
	if (!entry) return;

	if (what & BEV_EVENT_CONNECTED) {
		/* TCP connect succeeded */
		debug(LOG_DEBUG, "Health check [%s]: TCP check PASSED", entry->proxy_name);
		hc_finish_check(entry, 1);
	} else {
		/* Connect failed or timeout */
		if (what & BEV_EVENT_TIMEOUT) {
			debug(LOG_DEBUG, "Health check [%s]: TCP check TIMEOUT", entry->proxy_name);
		} else {
			debug(LOG_DEBUG, "Health check [%s]: TCP check FAILED (what=0x%x)",
				  entry->proxy_name, what);
		}
		hc_finish_check(entry, 0);
	}
}

/* ---- internal: HTTP check event callback ---- */

static void hc_http_event_cb(struct bufferevent *bev, short what, void *arg)
{
	struct health_check_entry *entry = (struct health_check_entry *)arg;
	if (!entry) return;

	if (what & BEV_EVENT_CONNECTED) {
		/* TCP connected, now send HTTP GET */
		entry->state = HC_SENDING;

		struct proxy_service *ps = entry->ps;
		const char *url = entry->check_url ? entry->check_url : "/";
		const char *host = ps->local_ip;

		char request[512];
		int n = snprintf(request, sizeof(request),
						 "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
						 url, host);

		bufferevent_write(bev, request, n);

		/* Switch to reading response */
		entry->state = HC_READING;
		bufferevent_setcb(bev, hc_http_read_cb, NULL, hc_http_event_cb, entry);

	} else {
		/* Connect failed or timeout */
		if (what & BEV_EVENT_TIMEOUT) {
			debug(LOG_DEBUG, "Health check [%s]: HTTP check TIMEOUT", entry->proxy_name);
		} else {
			debug(LOG_DEBUG, "Health check [%s]: HTTP check FAILED (what=0x%x)",
				  entry->proxy_name, what);
		}
		hc_finish_check(entry, 0);
	}
}

/* ---- internal: HTTP response reader ---- */

static void hc_http_read_cb(struct bufferevent *bev, void *arg)
{
	struct health_check_entry *entry = (struct health_check_entry *)arg;
	if (!entry) return;

	struct evbuffer *input = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(input);
	if (len == 0)
		return;

	/* Read the response */
	char *data = malloc(len + 1);
	if (!data) {
		hc_finish_check(entry, 0);
		return;
	}

	evbuffer_remove(input, data, len);
	data[len] = '\0';

	/* Parse HTTP status line: "HTTP/1.x NNN ..." */
	int status_code = 0;
	if (sscanf(data, "HTTP/%*d.%*d %d", &status_code) == 1) {
		if (status_code >= 200 && status_code < 400) {
			debug(LOG_DEBUG, "Health check [%s]: HTTP check PASSED (status=%d)",
				  entry->proxy_name, status_code);
			hc_finish_check(entry, 1);
		} else {
			debug(LOG_DEBUG, "Health check [%s]: HTTP check FAILED (status=%d)",
				  entry->proxy_name, status_code);
			hc_finish_check(entry, 0);
		}
	} else {
		debug(LOG_DEBUG, "Health check [%s]: HTTP check FAILED (bad response)",
			  entry->proxy_name);
		hc_finish_check(entry, 0);
	}

	free(data);
}

/* ---- internal: finalize a check and schedule next ---- */

static void hc_finish_check(struct health_check_entry *entry, int healthy)
{
	if (!entry) return;

	/* Clean up connection */
	if (entry->check_bev) {
		bufferevent_free(entry->check_bev);
		entry->check_bev = NULL;
	}
	entry->state = HC_IDLE;

	int was_healthy = entry->is_healthy;

	if (healthy) {
		entry->failed_count = 0;
		entry->is_healthy = 1;
	} else {
		entry->failed_count++;
		if (entry->failed_count >= entry->max_failed) {
			entry->is_healthy = 0;
		}
	}

	/* Notify on state transition */
	if (was_healthy != entry->is_healthy) {
		if (entry->is_healthy) {
			debug(LOG_INFO, "Health check [%s]: RECOVERED (consecutive failures reset)",
				  entry->proxy_name);
		} else {
			debug(LOG_WARNING, "Health check [%s]: DOWN after %d consecutive failures",
				  entry->proxy_name, entry->failed_count);
		}

		if (entry->callback) {
			entry->callback(entry->ps, entry->is_healthy, entry->ctx);
		}
	}

	hc_schedule_next(entry);
}

static void hc_schedule_next(struct health_check_entry *entry)
{
	if (!entry || !entry->timer)
		return;

	struct timeval tv = {entry->interval, 0};
	evtimer_add(entry->timer, &tv);
}
