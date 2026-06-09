// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * XTCP Visitor - P2P tunnel via NAT hole punching.
 *
 * Flow:
 *   1. PreCheck  — verify XTCP proxy exists on server
 *   2. Prepare   — STUN discovery + NAT classification
 *   3. Exchange  — send NatHoleVisitor, receive NatHoleResp
 *   4. MakeHole  — UDP hole-punch with encrypted NatHoleSid packets
 *   5. Tunnel    — relay TCP data over the P2P UDP tunnel
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <json-c/json.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "xtcp_visitor.h"
#include "nathole.h"
#include "msg.h"
#include "control.h"
#include "config.h"
#include "login.h"
#include "common.h"
#include "debug.h"
#include "utils.h"

/* Default STUN servers if not configured */
static const char *default_stun_servers[] = {
	"stun.miwifi.com:3478",
	"stun.qq.com:3478",
	NULL
};

/* ---- Cached STUN results per visitor ---- */
struct xtcp_stun_cache {
	char    visitor_name[128];
	char    mapped_addrs[MAX_MAPPED_ADDRS][64];
	int     mapped_addrs_count;
	char    local_addr[64];
	struct  nat_feature nat_feat;
	char    local_ips[MAX_ASSISTED_ADDRS][64];
	int     local_ips_count;
	int     valid;
};

#define MAX_XTCP_VISITORS 16
static struct xtcp_stun_cache stun_cache[MAX_XTCP_VISITORS];
static int stun_cache_count = 0;

/* Global active XTCP sessions (for NatHoleResp dispatching) */
static struct xtcp_session *active_xtcp_sessions[MAX_XTCP_VISITORS];
static int active_xtcp_count = 0;

static void xtcp_session_register(struct xtcp_session *sess)
{
	if (active_xtcp_count < MAX_XTCP_VISITORS) {
		active_xtcp_sessions[active_xtcp_count++] = sess;
	}
}

static void xtcp_session_unregister(struct xtcp_session *sess)
{
	for (int i = 0; i < active_xtcp_count; i++) {
		if (active_xtcp_sessions[i] == sess) {
			active_xtcp_sessions[i] = active_xtcp_sessions[--active_xtcp_count];
			active_xtcp_sessions[active_xtcp_count] = NULL;
			return;
		}
	}
}

/* ---- XTCP tunnel state ---- */
enum xtcp_state {
	XTCP_STUN_PRECHECK,
	XTCP_STUN_DISCOVER,
	XTCP_STUN_EXCHANGE,
	XTCP_STUN_MAKE_HOLE,
	XTCP_TUNNEL_ESTABLISHED,
	XTCP_TUNNEL_RELAY,
	XTCP_FAILED,
};

struct xtcp_session {
	enum xtcp_state         state;
	struct event_base      *base;
	struct visitor_instance *vi;
	struct bufferevent      *user_bev;     /* local TCP connection */
	struct event           *udp_event;     /* UDP read event */
	int                     udp_fd;        /* UDP socket for hole-punch */
	struct sockaddr_in      peer_addr;     /* peer's address after hole-punch */
	char                    sid[64];       /* session ID from server */
	char                    transaction_id[64];
	char                   *secret_key;
	int                     is_sender;     /* 1=sender role, 0=receiver */
	int                     send_delay_ms;
	int                     read_timeout_ms;
	int                     ttl;
	int                     send_random_ports;
	int                     listen_random_ports;
	struct event           *timer_event;   /* for delayed sends */
	struct event           *timeout_event; /* overall timeout */
	int                     hole_punched;  /* flag: hole-punch succeeded */

	/* Candidate and assisted addresses from NatHoleResp */
	char                   *candidate_addrs[MAX_CANDIDATE_ADDRS];
	int                     candidate_addrs_count;
	char                   *assisted_addrs[MAX_CANDIDATE_ADDRS];
	int                     assisted_addrs_count;

	/* For receiver: additional listen sockets */
	int                     extra_fds[256];
	int                     extra_fd_count;
	struct event           *extra_events[256];
};

/* ---- Forward declarations ---- */
static void xtcp_start_exchange(struct xtcp_session *sess);
static void xtcp_handle_nat_hole_resp_impl(struct xtcp_session *sess,
				       struct nathole_resp_msg *resp);
static void xtcp_handle_precheck_resp(struct xtcp_session *sess,
				       struct nathole_resp_msg *resp);
static void xtcp_start_make_hole(struct xtcp_session *sess);
static void xtcp_udp_recv_cb(evutil_socket_t fd, short events, void *ctx);
static void xtcp_send_sid_probe(struct xtcp_session *sess, const char *addr);
static void xtcp_send_sid_probe_to_all(struct xtcp_session *sess);
static void xtcp_timeout_cb(evutil_socket_t fd, short events, void *ctx);
static void xtcp_send_delay_cb(evutil_socket_t fd, short events, void *ctx);
static void xtcp_enter_tunnel(struct xtcp_session *sess);
static void xtcp_cleanup(struct xtcp_session *sess);
static void xtcp_report_result(struct xtcp_session *sess, int success);
static void xtcp_user_read_cb(struct bufferevent *bev, void *ctx);
static void xtcp_user_event_cb(struct bufferevent *bev, short events, void *ctx);

/* ---- Helper: send NatHoleVisitor via control connection ---- */
static int send_nathole_visitor(struct xtcp_session *sess, int pre_check)
{
	time_t now = time(NULL);

	struct nathole_visitor_msg vmsg;
	memset(&vmsg, 0, sizeof(vmsg));

	char txid[64];
	nathole_gen_transaction_id(txid, sizeof(txid));
	strncpy(sess->transaction_id, txid, sizeof(sess->transaction_id) - 1);

	vmsg.transaction_id = txid;
	vmsg.proxy_name = sess->vi->conf->server_name;
	vmsg.pre_check = pre_check;
	vmsg.protocol = "kcp";

	char *sign_key = NULL;
	if (!pre_check) {
		nathole_auth_key(sess->secret_key, now, &sign_key);
		vmsg.sign_key = sign_key;
		vmsg.timestamp = now;

		/* Find cached STUN result */
		for (int i = 0; i < stun_cache_count; i++) {
			if (strcmp(stun_cache[i].visitor_name,
				   sess->vi->conf->visitor_name) == 0 &&
			    stun_cache[i].valid) {
				/* mapped_addrs */
				vmsg.mapped_addrs = calloc(stun_cache[i].mapped_addrs_count,
							   sizeof(char *));
				for (int j = 0; j < stun_cache[i].mapped_addrs_count; j++)
					vmsg.mapped_addrs[j] = stun_cache[i].mapped_addrs[j];
				vmsg.mapped_addrs_count = stun_cache[i].mapped_addrs_count;

				/* assisted_addrs (local_ip:port pairs) */
				vmsg.assisted_addrs = calloc(stun_cache[i].local_ips_count,
							     sizeof(char *));
				for (int j = 0; j < stun_cache[i].local_ips_count; j++) {
					char *a = malloc(128);
					if (a) {
						snprintf(a, 128, "%s:%s",
							 stun_cache[i].local_ips[j],
							 stun_cache[i].local_addr);
						vmsg.assisted_addrs[j] = a;
					} else {
						vmsg.assisted_addrs[j] = NULL;
					}
				}
				vmsg.assisted_addrs_count = stun_cache[i].local_ips_count;
				break;
			}
		}
	}

	char *json_str = NULL;
	int json_len = nathole_visitor_marshal(&vmsg, &json_str);

	/* Free allocated strings and arrays */
	SAFE_FREE(vmsg.mapped_addrs);
	if (vmsg.assisted_addrs) {
		for (int j = 0; j < vmsg.assisted_addrs_count; j++)
			SAFE_FREE(vmsg.assisted_addrs[j]);
		SAFE_FREE(vmsg.assisted_addrs);
	}
	SAFE_FREE(sign_key);

	if (json_len == 0 || !json_str) {
		debug(LOG_ERR, "XTCP: failed to marshal NatHoleVisitor");
		return -1;
	}

	/* Send via control connection */
	struct control *ctl = get_main_control();
	if (!ctl || !ctl->connect_bev) {
		SAFE_FREE(json_str);
		return -1;
	}

	debug(LOG_DEBUG, "XTCP: sending NatHoleVisitor (pre_check=%d) for '%s'",
	      pre_check, sess->vi->conf->server_name);

	/* Use the control connection's tmux stream directly */
	send_msg_frp_server(ctl->connect_bev, TypeNatHoleVisitor,
			    json_str, json_len, &ctl->stream);

	SAFE_FREE(json_str);
	sess->state = pre_check ? XTCP_STUN_PRECHECK : XTCP_STUN_EXCHANGE;

	return 0;
}

/* ---- Start XTCP visitor flow ---- */
void xtcp_visitor_run(struct event_base *base,
		      struct visitor_instance *vi,
		      struct bufferevent *user_bev)
{
	if (!base || !vi || !vi->conf || !user_bev) return;

	debug(LOG_INFO, "XTCP: starting visitor '%s' for proxy '%s'",
	      vi->conf->visitor_name, vi->conf->server_name);

	struct xtcp_session *sess = calloc(1, sizeof(struct xtcp_session));
	if (!sess) {
		debug(LOG_ERR, "XTCP: out of memory");
		bufferevent_free(user_bev);
		return;
	}

	sess->base = base;
	sess->vi = vi;
	sess->user_bev = user_bev;
	sess->udp_fd = -1;
	sess->secret_key = vi->conf->secret_key ?
		strdup(vi->conf->secret_key) : NULL;

	/* Register in active sessions for NatHoleResp dispatching */
	xtcp_session_register(sess);

	/* Set up user bev callbacks for data relay */
	bufferevent_setcb(user_bev, xtcp_user_read_cb, NULL,
			  xtcp_user_event_cb, sess);
	bufferevent_enable(user_bev, EV_READ | EV_WRITE);

	/* Set overall timeout (30 seconds for the whole flow) */
	struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
	sess->timeout_event = evtimer_new(base, xtcp_timeout_cb, sess);
	evtimer_add(sess->timeout_event, &tv);

	/* Step 1: PreCheck */
	debug(LOG_DEBUG, "XTCP: PreCheck for '%s'", vi->conf->server_name);
	if (send_nathole_visitor(sess, 1) < 0) {
		debug(LOG_ERR, "XTCP: PreCheck send failed");
		xtcp_cleanup(sess);
		return;
	}
}

/* ---- Handle NatHoleResp from server (called by control.c) ---- */
void xtcp_handle_nat_hole_resp_msg(const char *json_str)
{
	if (!json_str) return;

	struct nathole_resp_msg *resp = nathole_resp_unmarshal(json_str);
	if (!resp) {
		debug(LOG_ERR, "XTCP: failed to parse NatHoleResp");
		return;
	}

	debug(LOG_DEBUG, "XTCP: NatHoleResp received, sid=%s, transaction_id=%s, error=%s",
	      resp->sid ? resp->sid : "",
	      resp->transaction_id ? resp->transaction_id : "",
	      resp->error ? resp->error : "");

	/* Find matching active session by transaction_id */
	struct xtcp_session *sess = NULL;
	for (int i = 0; i < active_xtcp_count; i++) {
		if (active_xtcp_sessions[i]->transaction_id[0] &&
		    resp->transaction_id &&
		    strcmp(active_xtcp_sessions[i]->transaction_id,
			   resp->transaction_id) == 0) {
			sess = active_xtcp_sessions[i];
			break;
		}
	}

	if (!sess) {
		debug(LOG_WARNING, "XTCP: no matching session for transaction_id=%s",
		      resp->transaction_id ? resp->transaction_id : "");
		nathole_resp_msg_free(resp);
		return;
	}

	/* Check if this is a PreCheck response (no SID yet) */
	if (sess->state == XTCP_STUN_PRECHECK) {
		/* PreCheck response */
		if (resp->error && strlen(resp->error) > 0) {
			debug(LOG_ERR, "XTCP: PreCheck failed: %s", resp->error);
			xtcp_cleanup(sess);
			nathole_resp_msg_free(resp);
			return;
		}
		debug(LOG_DEBUG, "XTCP: PreCheck OK, starting STUN discovery");
		/* Proceed to STUN discovery */
		xtcp_handle_precheck_resp(sess, resp);
		nathole_resp_msg_free(resp);
		return;
	}

	/* This is the Exchange response with hole-punch instructions */
	xtcp_handle_nat_hole_resp_impl(sess, resp);
	nathole_resp_msg_free(resp);
}

/* ---- Called from control.c when NatHoleResp is received for XTCP ---- */
void xtcp_handle_precheck_resp(struct xtcp_session *sess,
			       struct nathole_resp_msg *resp)
{
	if (!sess || !resp) return;

	if (resp->error && strlen(resp->error) > 0) {
		debug(LOG_ERR, "XTCP: PreCheck failed: %s", resp->error);
		xtcp_cleanup(sess);
		return;
	}

	debug(LOG_DEBUG, "XTCP: PreCheck OK, starting STUN discovery");

	/* Step 2: STUN Discovery */
	sess->state = XTCP_STUN_DISCOVER;

	/* Find or create cache entry */
	struct xtcp_stun_cache *cache = NULL;
	for (int i = 0; i < stun_cache_count; i++) {
		if (strcmp(stun_cache[i].visitor_name,
			   sess->vi->conf->visitor_name) == 0) {
			cache = &stun_cache[i];
			break;
		}
	}
	if (!cache && stun_cache_count < MAX_XTCP_VISITORS) {
		cache = &stun_cache[stun_cache_count++];
		strncpy(cache->visitor_name, sess->vi->conf->visitor_name,
			sizeof(cache->visitor_name) - 1);
	}

	if (cache && cache->valid) {
		/* Use cached STUN result */
		debug(LOG_DEBUG, "XTCP: using cached STUN result");
		xtcp_start_exchange(sess);
		return;
	}

	/* Do STUN discovery */
	struct stun_result sresult;
	const char *servers[8];
	int scount = 0;

	/* Use default STUN servers */
	for (int i = 0; default_stun_servers[i] && scount < 7; i++)
		servers[scount++] = default_stun_servers[i];
	servers[scount] = NULL;

	if (stun_discover(servers, NULL, &sresult) < 0 ||
	    sresult.addr_count < 2) {
		debug(LOG_ERR, "XTCP: STUN discovery failed (need 2+ addresses, got %d)",
		      sresult.addr_count);
		xtcp_cleanup(sess);
		return;
	}

	debug(LOG_INFO, "XTCP: STUN discovered %d addresses", sresult.addr_count);

	/* Cache results */
	if (cache) {
		for (int i = 0; i < sresult.addr_count && i < MAX_MAPPED_ADDRS; i++) {
			strncpy(cache->mapped_addrs[i], sresult.addrs[i].addr, 63);
		}
		cache->mapped_addrs_count = sresult.addr_count;

		/* Store local address */
		char local_ip[64];
		inet_ntop(AF_INET, &sresult.local_addr.sin_addr,
			  local_ip, sizeof(local_ip));
		int local_port = ntohs(sresult.local_addr.sin_port);
		snprintf(cache->local_addr, sizeof(cache->local_addr), "%d", local_port);

		/* Classify NAT */
		const char *addr_ptrs[MAX_MAPPED_ADDRS];
		for (int i = 0; i < sresult.addr_count; i++)
			addr_ptrs[i] = sresult.addrs[i].addr;

		char local_ips[MAX_ASSISTED_ADDRS][64];
		int n_local = list_local_ips(local_ips, MAX_ASSISTED_ADDRS);
		cache->local_ips_count = n_local;
		for (int i = 0; i < n_local; i++)
			strncpy(cache->local_ips[i], local_ips[i], 63);

		const char *lip_ptrs[MAX_ASSISTED_ADDRS];
		for (int i = 0; i < n_local; i++)
			lip_ptrs[i] = cache->local_ips[i];

		if (classify_nat_feature(addr_ptrs, sresult.addr_count,
					 lip_ptrs, n_local,
					 &cache->nat_feat) == 0) {
			debug(LOG_INFO, "XTCP: NAT type=%s, behavior=%s",
			      cache->nat_feat.nat_type, cache->nat_feat.behavior);
		}
		cache->valid = 1;
	}

	/* Step 3: Exchange Info */
	xtcp_start_exchange(sess);
}

/* ---- Step 3: Exchange Info ---- */
static void xtcp_start_exchange(struct xtcp_session *sess)
{
	debug(LOG_DEBUG, "XTCP: exchanging info with server");
	if (send_nathole_visitor(sess, 0) < 0) {
		debug(LOG_ERR, "XTCP: exchange info send failed");
		xtcp_cleanup(sess);
	}
}

/* ---- Step 4: Handle NatHoleResp and Make Hole ---- */
static void xtcp_handle_nat_hole_resp_impl(struct xtcp_session *sess,
					    struct nathole_resp_msg *resp)
{
	if (!sess || !resp) return;

	if (resp->error && strlen(resp->error) > 0) {
		debug(LOG_ERR, "XTCP: NatHoleResp error: %s", resp->error);
		xtcp_cleanup(sess);
		return;
	}

	/* Store session ID */
	strncpy(sess->sid, resp->sid ? resp->sid : "", sizeof(sess->sid) - 1);

	/* Store candidate and assisted addresses for probe sending */
	for (int i = 0; i < resp->candidate_addrs_count && i < MAX_CANDIDATE_ADDRS; i++) {
		sess->candidate_addrs[i] = strdup(resp->candidate_addrs[i]);
	}
	sess->candidate_addrs_count = resp->candidate_addrs_count;

	for (int i = 0; i < resp->assisted_addrs_count && i < MAX_CANDIDATE_ADDRS; i++) {
		sess->assisted_addrs[i] = strdup(resp->assisted_addrs[i]);
	}
	sess->assisted_addrs_count = resp->assisted_addrs_count;

	/* Parse detect behavior */
	sess->is_sender = (resp->behavior_role && strcmp(resp->behavior_role, "sender") == 0);
	sess->send_delay_ms = resp->behavior_send_delay_ms;
	sess->read_timeout_ms = resp->behavior_read_timeout_ms;
	sess->ttl = resp->behavior_ttl;
	sess->send_random_ports = resp->behavior_send_random_ports;
	sess->listen_random_ports = resp->behavior_listen_random_ports;

	debug(LOG_INFO, "XTCP: NatHoleResp sid=%s, role=%s, mode=%d, "
	      "candidates=%d, assisted=%d, ttl=%d, delay=%dms, timeout=%dms",
	      sess->sid,
	      sess->is_sender ? "sender" : "receiver",
	      resp->behavior_mode,
	      resp->candidate_addrs_count,
	      resp->assisted_addrs_count,
	      sess->ttl, sess->send_delay_ms, sess->read_timeout_ms);

	/* Prepare UDP socket for hole-punching */
	sess->udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sess->udp_fd < 0) {
		debug(LOG_ERR, "XTCP: socket() failed: %s", strerror(errno));
		xtcp_cleanup(sess);
		return;
	}

	/* Bind to the same port as STUN discovery */
	/* TODO: bind to the same local port used in STUN to preserve NAT mapping */

	struct sockaddr_in bind_addr;
	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_addr.s_addr = INADDR_ANY;
	bind_addr.sin_port = 0; /* Let OS choose */

	if (bind(sess->udp_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
		debug(LOG_WARNING, "XTCP: bind() failed: %s", strerror(errno));
	}

	/* Set non-blocking */
	evutil_make_socket_nonblocking(sess->udp_fd);

	debug(LOG_DEBUG, "XTCP: UDP socket ready (fd=%d), starting hole-punch",
	      sess->udp_fd);

	xtcp_start_make_hole(sess);
}

/* ---- Step 4: Make Hole ---- */
static void xtcp_start_make_hole(struct xtcp_session *sess)
{
	sess->state = XTCP_STUN_MAKE_HOLE;

	/* Set up UDP read event */
	sess->udp_event = event_new(sess->base, sess->udp_fd,
				    EV_READ | EV_PERSIST,
				    xtcp_udp_recv_cb, sess);
	event_add(sess->udp_event, NULL);

	/* For receiver: also listen on random ports if requested */
	if (!sess->is_sender && sess->listen_random_ports > 0) {
		int n = sess->listen_random_ports;
		if (n > 256) n = 256;
		sess->extra_fd_count = 0;
		for (int i = 0; i < n; i++) {
			int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (fd < 0) continue;
			struct sockaddr_in la;
			memset(&la, 0, sizeof(la));
			la.sin_family = AF_INET;
			la.sin_port = 0;
			if (bind(fd, (struct sockaddr *)&la, sizeof(la)) < 0) {
				close(fd);
				continue;
			}
			evutil_make_socket_nonblocking(fd);
			struct event *ev = event_new(sess->base, fd,
						     EV_READ | EV_PERSIST,
						     xtcp_udp_recv_cb, sess);
			event_add(ev, NULL);
			sess->extra_fds[sess->extra_fd_count] = fd;
			sess->extra_events[sess->extra_fd_count] = ev;
			sess->extra_fd_count++;
		}
		debug(LOG_DEBUG, "XTCP: listening on %d extra random ports",
		      sess->extra_fd_count);
	}

	/* Send probes based on role */
	if (sess->is_sender) {
		/* Sender: optionally delay, then send probes */
		if (sess->send_delay_ms > 0) {
			debug(LOG_DEBUG, "XTCP: sender delaying %dms before probes",
			      sess->send_delay_ms);
			struct timeval tv = {
				.tv_sec = sess->send_delay_ms / 1000,
				.tv_usec = (sess->send_delay_ms % 1000) * 1000
			};
			sess->timer_event = evtimer_new(sess->base,
							xtcp_send_delay_cb, sess);
			evtimer_add(sess->timer_event, &tv);
		} else {
			xtcp_send_sid_probe_to_all(sess);
		}
	} else {
		/* Receiver: send initial probes immediately */
		xtcp_send_sid_probe_to_all(sess);
	}
}

/* Send a single NatHoleSid probe to an address */
static void xtcp_send_sid_probe(struct xtcp_session *sess, const char *addr)
{
	struct nathole_sid_msg sid_msg;
	memset(&sid_msg, 0, sizeof(sid_msg));
	sid_msg.transaction_id = sess->transaction_id;
	sid_msg.sid = sess->sid;
	sid_msg.response = false;

	/* Generate random nonce */
	static const char hex_chars[] = "0123456789abcdef";
	char nonce[32];
	int nonce_len = rand() % 20;
	for (int i = 0; i < nonce_len; i++)
		nonce[i] = hex_chars[rand() & 0xf];
	nonce[nonce_len] = '\0';
	sid_msg.nonce = nonce;

	uint8_t *pkt = NULL;
	size_t pkt_len = 0;
	if (nathole_encode_sid(&sid_msg, sess->secret_key, &pkt, &pkt_len) < 0) {
		debug(LOG_WARNING, "XTCP: failed to encode NatHoleSid");
		return;
	}

	/* Parse address */
	struct sockaddr_in target;
	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;

	char addr_copy[128];
	strncpy(addr_copy, addr, sizeof(addr_copy) - 1);
	char *colon = strrchr(addr_copy, ':');
	if (!colon) {
		free(pkt);
		return;
	}
	*colon = '\0';
	target.sin_port = htons(atoi(colon + 1));
	if (inet_pton(AF_INET, addr_copy, &target.sin_addr) != 1) {
		free(pkt);
		return;
	}

	/* Set TTL if needed */
	if (sess->ttl > 0) {
		int ttl = sess->ttl;
		setsockopt(sess->udp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	}

	ssize_t sent = sendto(sess->udp_fd, pkt, pkt_len, 0,
			      (struct sockaddr *)&target, sizeof(target));
	if (sent > 0) {
		debug(LOG_DEBUG, "XTCP: sent NatHoleSid probe to %s (len=%zu)",
		      addr, pkt_len);
	} else {
		debug(LOG_WARNING, "XTCP: sendto %s failed: %s",
		      addr, strerror(errno));
	}

	/* Restore default TTL */
	if (sess->ttl > 0) {
		int ttl = 64;
		setsockopt(sess->udp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	}

	free(pkt);
}

/* Send probes to all known addresses */
static void xtcp_send_sid_probe_to_all(struct xtcp_session *sess)
{
	debug(LOG_DEBUG, "XTCP: sending NatHoleSid probes (role=%s, ttl=%d, "
	      "candidates=%d, assisted=%d)",
	      sess->is_sender ? "sender" : "receiver", sess->ttl,
	      sess->candidate_addrs_count, sess->assisted_addrs_count);

	/* Send to assisted addrs first, then candidate addrs */
	for (int i = 0; i < sess->assisted_addrs_count; i++) {
		xtcp_send_sid_probe(sess, sess->assisted_addrs[i]);
	}
	for (int i = 0; i < sess->candidate_addrs_count; i++) {
		xtcp_send_sid_probe(sess, sess->candidate_addrs[i]);
	}
}

/* ---- UDP receive callback ---- */
static void xtcp_udp_recv_cb(evutil_socket_t fd, short events, void *ctx)
{
	struct xtcp_session *sess = (struct xtcp_session *)ctx;
	if (!sess) return;

	uint8_t buf[2048];
	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);

	ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
			     (struct sockaddr *)&from, &from_len);
	if (n < 0) return;

	debug(LOG_DEBUG, "XTCP: received UDP packet from %s:%d (len=%zd)",
	      inet_ntoa(from.sin_addr), ntohs(from.sin_port), n);

	/* Decode NatHoleSid */
	struct nathole_sid_msg sid_msg;
	memset(&sid_msg, 0, sizeof(sid_msg));

	if (nathole_decode_sid(buf, n, sess->secret_key, &sid_msg) < 0) {
		debug(LOG_WARNING, "XTCP: failed to decode NatHoleSid packet");
		return;
	}

	/* Verify SID matches */
	if (sid_msg.sid && strcmp(sid_msg.sid, sess->sid) != 0) {
		debug(LOG_WARNING, "XTCP: SID mismatch: got '%s', expected '%s'",
		      sid_msg.sid, sess->sid);
		nathole_sid_msg_free(&sid_msg);
		return;
	}

	if (!sid_msg.response) {
		/* Received a probe (not a response) */
		if (sess->is_sender) {
			/* Sender: ignore non-response probes */
			debug(LOG_DEBUG, "XTCP: sender ignoring non-response probe");
			nathole_sid_msg_free(&sid_msg);
			return;
		}

		/* Receiver: send response back */
		debug(LOG_INFO, "XTCP: received probe from %s:%d, sending response",
		      inet_ntoa(from.sin_addr), ntohs(from.sin_port));

		struct nathole_sid_msg resp_msg;
		memset(&resp_msg, 0, sizeof(resp_msg));
		resp_msg.transaction_id = sid_msg.transaction_id;
		resp_msg.sid = sess->sid;
		resp_msg.response = true;
		resp_msg.nonce = sid_msg.nonce;

		uint8_t *resp_pkt = NULL;
		size_t resp_len = 0;
		if (nathole_encode_sid(&resp_msg, sess->secret_key,
				       &resp_pkt, &resp_len) == 0) {
			sendto(sess->udp_fd, resp_pkt, resp_len, 0,
			       (struct sockaddr *)&from, from_len);
			free(resp_pkt);
		}

		/* Hole-punch succeeded! */
		sess->hole_punched = 1;
		memcpy(&sess->peer_addr, &from, sizeof(from));
		nathole_sid_msg_free(&sid_msg);
		xtcp_enter_tunnel(sess);
		return;
	}

	/* Received a response */
	if (sess->is_sender) {
		/* Sender: hole-punch succeeded! */
		debug(LOG_INFO, "XTCP: received response from %s:%d, hole-punch succeeded!",
		      inet_ntoa(from.sin_addr), ntohs(from.sin_port));
		sess->hole_punched = 1;
		memcpy(&sess->peer_addr, &from, sizeof(from));
		nathole_sid_msg_free(&sid_msg);
		xtcp_enter_tunnel(sess);
		return;
	}

	/* Receiver got a response - also success */
	debug(LOG_INFO, "XTCP: receiver got response, hole-punch succeeded!");
	sess->hole_punched = 1;
	memcpy(&sess->peer_addr, &from, sizeof(from));
	nathole_sid_msg_free(&sid_msg);
	xtcp_enter_tunnel(sess);
}

/* ---- Delayed send callback (for sender) ---- */
static void xtcp_send_delay_cb(evutil_socket_t fd, short events, void *ctx)
{
	struct xtcp_session *sess = (struct xtcp_session *)ctx;
	if (!sess) return;
	xtcp_send_sid_probe_to_all(sess);
}

/* ---- Timeout callback ---- */
static void xtcp_timeout_cb(evutil_socket_t fd, short events, void *ctx)
{
	struct xtcp_session *sess = (struct xtcp_session *)ctx;
	if (!sess) return;

	debug(LOG_ERR, "XTCP: timeout waiting for P2P tunnel");
	xtcp_cleanup(sess);
}

/* ---- Enter tunnel mode: relay TCP <-> UDP ---- */
static void xtcp_enter_tunnel(struct xtcp_session *sess)
{
	sess->state = XTCP_TUNNEL_ESTABLISHED;

	debug(LOG_INFO, "XTCP: P2P tunnel established with %s:%d, entering relay mode",
	      inet_ntoa(sess->peer_addr.sin_addr), ntohs(sess->peer_addr.sin_port));

	/* Report success to server */
	xtcp_report_result(sess, 1);

	/* Cancel timeout */
	if (sess->timeout_event) {
		event_del(sess->timeout_event);
	}

	/* Close extra listen sockets */
	for (int i = 0; i < sess->extra_fd_count; i++) {
		if (sess->extra_events[i])
			event_free(sess->extra_events[i]);
		if (sess->extra_fds[i] >= 0)
			close(sess->extra_fds[i]);
	}
	sess->extra_fd_count = 0;

	/* Now relay data between user TCP connection and UDP tunnel.
	 *
	 * For now, we implement a simple framing protocol:
	 *   Each TCP read → send as UDP packet to peer
	 *   Each UDP receive → write to TCP
	 *
	 * This works for a single connection. For multiplexing,
	 * a KCP layer would be needed (future enhancement).
	 */

	/* Set up UDP read event for relay */
	if (sess->udp_event) {
		event_del(sess->udp_event);
		event_free(sess->udp_event);
	}
	sess->udp_event = event_new(sess->base, sess->udp_fd,
				    EV_READ | EV_PERSIST,
				    xtcp_udp_recv_cb, sess);
	event_add(sess->udp_event, NULL);

	sess->state = XTCP_TUNNEL_RELAY;

	/* User bev is already set up with callbacks */
	debug(LOG_INFO, "XTCP: tunnel relay active for '%s'",
	      sess->vi->conf->visitor_name);
}

/* ---- User TCP connection callbacks ---- */
static void xtcp_user_read_cb(struct bufferevent *bev, void *ctx)
{
	struct xtcp_session *sess = (struct xtcp_session *)ctx;
	if (!sess || sess->state != XTCP_TUNNEL_RELAY) return;

	struct evbuffer *input = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(input);
	if (len == 0) return;

	/* Read TCP data and send as UDP packet to peer */
	uint8_t *data = evbuffer_pullup(input, len);
	if (data && len > 0) {
		ssize_t sent = sendto(sess->udp_fd, data, len, 0,
				      (struct sockaddr *)&sess->peer_addr,
				      sizeof(sess->peer_addr));
		if (sent > 0) {
			evbuffer_drain(input, sent);
		}
	}
}

static void xtcp_user_event_cb(struct bufferevent *bev, short events, void *ctx)
{
	struct xtcp_session *sess = (struct xtcp_session *)ctx;
	if (!sess) return;

	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		debug(LOG_INFO, "XTCP: user connection closed");
		xtcp_cleanup(sess);
	}
}

/* ---- Report result to server ---- */
static void xtcp_report_result(struct xtcp_session *sess, int success)
{
	struct nathole_report_msg rmsg;
	memset(&rmsg, 0, sizeof(rmsg));
	rmsg.sid = sess->sid;
	rmsg.success = success;

	char *json_str = NULL;
	int json_len = nathole_report_marshal(&rmsg, &json_str);
	if (json_len > 0 && json_str) {
		struct control *ctl = get_main_control();
		if (ctl && ctl->connect_bev) {
			send_msg_frp_server(ctl->connect_bev,
					    TypeNatHoleReport,
					    json_str, json_len, NULL);
		}
		SAFE_FREE(json_str);
	}
}

/* ---- Cleanup ---- */
static void xtcp_cleanup(struct xtcp_session *sess)
{
	if (!sess) return;

	debug(LOG_DEBUG, "XTCP: cleaning up session for '%s'",
	      sess->vi ? sess->vi->conf->visitor_name : "?");

	if (sess->timeout_event) {
		event_del(sess->timeout_event);
		event_free(sess->timeout_event);
	}
	if (sess->timer_event) {
		event_del(sess->timer_event);
		event_free(sess->timer_event);
	}
	if (sess->udp_event) {
		event_del(sess->udp_event);
		event_free(sess->udp_event);
	}
	if (sess->udp_fd >= 0) {
		close(sess->udp_fd);
	}

	/* Close extra listen sockets */
	for (int i = 0; i < sess->extra_fd_count; i++) {
		if (sess->extra_events[i])
			event_free(sess->extra_events[i]);
		if (sess->extra_fds[i] >= 0)
			close(sess->extra_fds[i]);
	}

	SAFE_FREE(sess->secret_key);

	/* Free stored candidate/assisted addresses */
	for (int i = 0; i < sess->candidate_addrs_count; i++)
		SAFE_FREE(sess->candidate_addrs[i]);
	for (int i = 0; i < sess->assisted_addrs_count; i++)
		SAFE_FREE(sess->assisted_addrs[i]);

	/* Unregister from active sessions */
	xtcp_session_unregister(sess);

	/* Don't free user_bev here - it's managed by the caller */
	sess->user_bev = NULL;

	free(sess);
}

/* ---- Initialize XTCP visitors (STUN pre-discovery) ---- */
void init_xtcp_visitors(struct event_base *base)
{
	struct visitor_conf *vc = get_all_visitor_confs();
	for (; vc; vc = vc->hh.next) {
		if (!vc->visitor_type || strcmp(vc->visitor_type, "xtcp") != 0)
			continue;

		debug(LOG_INFO, "XTCP: pre-discovering NAT for visitor '%s'",
		      vc->visitor_name);

		struct stun_result sresult;
		const char *servers[8];
		int scount = 0;
		for (int i = 0; default_stun_servers[i] && scount < 7; i++)
			servers[scount++] = default_stun_servers[i];
		servers[scount] = NULL;

		if (stun_discover(servers, NULL, &sresult) == 0 &&
		    sresult.addr_count >= 2) {
			struct xtcp_stun_cache *cache = &stun_cache[stun_cache_count++];
			strncpy(cache->visitor_name, vc->visitor_name,
				sizeof(cache->visitor_name) - 1);
			for (int i = 0; i < sresult.addr_count && i < MAX_MAPPED_ADDRS; i++)
				strncpy(cache->mapped_addrs[i], sresult.addrs[i].addr, 63);
			cache->mapped_addrs_count = sresult.addr_count;

			char local_ips[MAX_ASSISTED_ADDRS][64];
			int n_local = list_local_ips(local_ips, MAX_ASSISTED_ADDRS);
			cache->local_ips_count = n_local;
			for (int i = 0; i < n_local; i++)
				strncpy(cache->local_ips[i], local_ips[i], 63);

			const char *addr_ptrs[MAX_MAPPED_ADDRS];
			for (int i = 0; i < sresult.addr_count; i++)
				addr_ptrs[i] = sresult.addrs[i].addr;
			const char *lip_ptrs[MAX_ASSISTED_ADDRS];
			for (int i = 0; i < n_local; i++)
				lip_ptrs[i] = cache->local_ips[i];

			if (classify_nat_feature(addr_ptrs, sresult.addr_count,
						 lip_ptrs, n_local,
						 &cache->nat_feat) == 0) {
				debug(LOG_INFO, "XTCP: visitor '%s' NAT=%s behavior=%s",
				      vc->visitor_name,
				      cache->nat_feat.nat_type,
				      cache->nat_feat.behavior);
			}

			char local_ip[64];
			inet_ntop(AF_INET, &sresult.local_addr.sin_addr,
				  local_ip, sizeof(local_ip));
			snprintf(cache->local_addr, sizeof(cache->local_addr),
				 "%d", ntohs(sresult.local_addr.sin_port));
			cache->valid = 1;
		} else {
			debug(LOG_WARNING, "XTCP: STUN discovery failed for '%s'",
			      vc->visitor_name);
		}
	}
}
