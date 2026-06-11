// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * XTCP Client - P2P tunnel via NAT hole punching (client/proxy side).
 *
 * This implements the client (proxy) side of XTCP P2P traversal.
 * The visitor side is in xtcp_visitor.c.
 *
 * Flow:
 *   1. handle_type_start_work_conn() detects XTCP proxy → calls xtcp_client_run()
 *   2. STUN discovery + NAT classification
 *   3. Send NatHoleClient to server with STUN results
 *   4. Receive NatHoleResp with peer addresses + detect behavior
 *   5. UDP hole-punch with encrypted NatHoleSid packets
 *   6. Connect to local service, relay over P2P tunnel (QUIC/UDP)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/util.h>

#include "xtcp_client.h"
#include "nathole.h"
#include "msg.h"
#include "control.h"
#include "debug.h"
#include "config.h"
#include "utils.h"
#include "crypto.h"

#include <openssl/rand.h>

#ifdef HAVE_NGTCP2
#include "quic_transport.h"
#endif

/* ---- Constants ---- */
#define MAX_CACHED_CLIENTS  16
#define CLIENT_TIMEOUT_SEC  30

/* ---- XTCP Client Session States ---- */
enum xtcp_client_state {
	XTCP_CLI_STUN,          /* Doing STUN discovery */
	XTCP_CLI_WAIT_RESP,     /* Sent NatHoleClient, waiting for NatHoleResp */
	XTCP_CLI_MAKE_HOLE,     /* UDP hole-punching */
	XTCP_CLI_TUNNEL_EST,    /* Tunnel established */
	XTCP_CLI_RELAY,         /* Relaying data */
};

/* ---- XTCP Client Session ---- */
struct xtcp_client_session {
	struct event_base       *base;
	struct proxy_client     *client;        /* The proxy client from StartWorkConn */
	struct proxy_service    *ps;            /* Proxy service config */

	enum xtcp_client_state  state;
	char                    transaction_id[64];
	char                    sid[64];

	/* STUN results */
	int                     udp_fd;         /* UDP socket for STUN + hole-punch */
	struct sockaddr_in      peer_addr;      /* Peer address after hole-punch */
	int                     hole_punched;

	/* NatHoleResp data */
	char                   *candidate_addrs[MAX_CANDIDATE_ADDRS];
	int                     candidate_addrs_count;
	char                   *assisted_addrs[MAX_CANDIDATE_ADDRS];
	int                     assisted_addrs_count;

	/* Detect behavior */
	int                     is_sender;
	int                     send_delay_ms;
	int                     read_timeout_ms;
	int                     ttl;
	int                     send_random_ports;
	int                     listen_random_ports;

	/* Candidate port ranges from NatHoleResp */
	int                     candidate_ports_from[16];
	int                     candidate_ports_to[16];
	int                     candidate_ports_count;

	/* Events */
	struct event           *udp_event;
	struct event           *timeout_event;
	struct event           *timer_event;

	/* Extra listen sockets for random ports */
	int                     extra_fds[256];
	struct event           *extra_events[256];
	int                     extra_fd_count;

	/* QUIC transport */
#ifdef HAVE_NGTCP2
	struct quic_ctx        *quic;
#endif

	/* Local service connection */
	struct bufferevent      *local_bev;

	/* UDP reassembly buffer for raw relay */
	uint8_t                 udp_recv_buf[65536];
	size_t                  udp_recv_len;

	/* Tunnel encryption (raw UDP only) */
	struct frp_coder        *encoder;
	struct frp_coder        *decoder;
	int                      use_encryption;
	char                    *secret_key;
};

/* ---- Cached STUN results per proxy ---- */
struct xtcp_client_stun_cache {
	char    proxy_name[128];
	char    mapped_addrs[MAX_MAPPED_ADDRS][64];
	int     mapped_addrs_count;
	char    local_addr[64];
	struct  nat_feature nat_feat;
	char    local_ips[MAX_ASSISTED_ADDRS][64];
	int     local_ips_count;
	int     udp_fd;
	int     valid;
};

#define MAX_CACHED_PROXIES 16
static struct xtcp_client_stun_cache client_stun_cache[MAX_CACHED_PROXIES];
static int client_stun_cache_count = 0;

/* ---- Active client sessions for NatHoleResp dispatching ---- */
static struct xtcp_client_session *active_client_sessions[MAX_CACHED_CLIENTS];
static int active_client_count = 0;

static void xtcp_client_session_register(struct xtcp_client_session *sess)
{
	if (active_client_count < MAX_CACHED_CLIENTS) {
		active_client_sessions[active_client_count++] = sess;
	}
}

static void xtcp_client_session_unregister(struct xtcp_client_session *sess)
{
	for (int i = 0; i < active_client_count; i++) {
		if (active_client_sessions[i] == sess) {
			active_client_sessions[i] = active_client_sessions[--active_client_count];
			return;
		}
	}
}

/* ---- Forward declarations ---- */
static void xtcp_client_cleanup(struct xtcp_client_session *sess);
static void xtcp_client_start_exchange(struct xtcp_client_session *sess);
static void xtcp_client_handle_nat_hole_resp_impl(struct xtcp_client_session *sess,
						   struct nathole_resp_msg *resp);
static void xtcp_client_start_make_hole(struct xtcp_client_session *sess);
static void xtcp_client_enter_tunnel(struct xtcp_client_session *sess);
static void xtcp_client_report_result(struct xtcp_client_session *sess, int success);
static void xtcp_client_send_sid_probe_to_all(struct xtcp_client_session *sess);

/* ---- Default STUN servers ---- */
static const char *default_stun_servers[] = {
	"stun.miwifi.com",
	"stun.chat.bilibili.com",
	"stun.cloudflare.com",
	NULL
};

/* ---- Send NatHoleClient to server ---- */
static int send_nathole_client(struct xtcp_client_session *sess)
{
	struct nathole_client_msg cmsg;
	memset(&cmsg, 0, sizeof(cmsg));
	cmsg.transaction_id = sess->transaction_id;
	cmsg.proxy_name = sess->ps->proxy_name;
	cmsg.sid = sess->sid[0] ? sess->sid : NULL;

	/* Fill STUN results */
	struct xtcp_client_stun_cache *cache = NULL;
	for (int i = 0; i < client_stun_cache_count; i++) {
		if (strcmp(client_stun_cache[i].proxy_name,
			   sess->ps->proxy_name) == 0) {
			cache = &client_stun_cache[i];
			break;
		}
	}

	if (cache && cache->valid) {
		cmsg.mapped_addrs_count = cache->mapped_addrs_count;
		cmsg.mapped_addrs = calloc(cache->mapped_addrs_count, sizeof(char *));
		for (int i = 0; i < cache->mapped_addrs_count; i++)
			cmsg.mapped_addrs[i] = cache->mapped_addrs[i];

		cmsg.assisted_addrs_count = cache->local_ips_count;
		cmsg.assisted_addrs = calloc(cache->local_ips_count, sizeof(char *));
		for (int i = 0; i < cache->local_ips_count; i++)
			cmsg.assisted_addrs[i] = cache->local_ips[i];
	}

	char *json_str = NULL;
	int json_len = nathole_client_marshal(&cmsg, &json_str);

	/* Free the pointer arrays (not the strings they point to - those are in cache) */
	free(cmsg.mapped_addrs);
	free(cmsg.assisted_addrs);

	if (json_len == 0 || !json_str) {
		debug(LOG_ERR, "XTCP-CLIENT: failed to marshal NatHoleClient");
		return -1;
	}

	struct control *ctl = get_main_control();
	if (!ctl || !ctl->connect_bev) {
		free(json_str);
		return -1;
	}

	debug(LOG_DEBUG, "XTCP-CLIENT: sending NatHoleClient for '%s'",
	      sess->ps->proxy_name);

	send_msg_frp_server(ctl->connect_bev, TypeNatHoleClient,
			    json_str, json_len, &ctl->stream);

	free(json_str);
	sess->state = XTCP_CLI_WAIT_RESP;
	return 0;
}

/* ---- Timeout callback ---- */
static void xtcp_client_timeout_cb(evutil_socket_t fd, short events, void *ctx)
{
	struct xtcp_client_session *sess = ctx;
	(void)fd; (void)events;
	debug(LOG_ERR, "XTCP-CLIENT: timeout waiting for P2P tunnel");
	xtcp_client_cleanup(sess);
}

/* ---- Delayed send callback ---- */
static void xtcp_client_send_delay_cb(evutil_socket_t fd, short events, void *ctx)
{
	struct xtcp_client_session *sess = ctx;
	(void)fd; (void)events;
	xtcp_client_send_sid_probe_to_all(sess);
}

/* ---- UDP recv callback (hole-punch probes) ---- */
static void xtcp_client_udp_recv_cb(evutil_socket_t fd, short events, void *ctx)
{
	struct xtcp_client_session *sess = ctx;
	if (!sess) return;

	uint8_t buf[2048];
	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);

	ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
			     (struct sockaddr *)&from, &from_len);
	if (n < 0) return;

	debug(LOG_DEBUG, "XTCP-CLIENT: received UDP from %s:%d (len=%zd)",
	      inet_ntoa(from.sin_addr), ntohs(from.sin_port), n);

	struct nathole_sid_msg sid_msg;
	memset(&sid_msg, 0, sizeof(sid_msg));

	if (nathole_decode_sid(buf, n, sess->ps->sk, &sid_msg) < 0) {
		debug(LOG_WARNING, "XTCP-CLIENT: failed to decode NatHoleSid");
		return;
	}

	if (sid_msg.sid && strcmp(sid_msg.sid, sess->sid) != 0) {
		debug(LOG_WARNING, "XTCP-CLIENT: SID mismatch");
		nathole_sid_msg_free(&sid_msg);
		return;
	}

	if (!sid_msg.response) {
		/* Received a probe */
		if (sess->is_sender) {
			debug(LOG_DEBUG, "XTCP-CLIENT: sender ignoring non-response probe");
			nathole_sid_msg_free(&sid_msg);
			return;
		}

		/* Receiver: send response back */
		debug(LOG_INFO, "XTCP-CLIENT: received probe from %s:%d, sending response",
		      inet_ntoa(from.sin_addr), ntohs(from.sin_port));

		struct nathole_sid_msg resp_msg;
		memset(&resp_msg, 0, sizeof(resp_msg));
		resp_msg.transaction_id = sid_msg.transaction_id;
		resp_msg.sid = sess->sid;
		resp_msg.response = true;
		resp_msg.nonce = sid_msg.nonce;

		uint8_t *resp_pkt = NULL;
		size_t resp_len = 0;
		if (nathole_encode_sid(&resp_msg, sess->ps->sk,
				       &resp_pkt, &resp_len) == 0) {
			sendto(sess->udp_fd, resp_pkt, resp_len, 0,
			       (struct sockaddr *)&from, from_len);
			free(resp_pkt);
		}

		sess->hole_punched = 1;
		memcpy(&sess->peer_addr, &from, sizeof(from));
		nathole_sid_msg_free(&sid_msg);
		xtcp_client_enter_tunnel(sess);
		return;
	}

	/* Received a response - hole-punch succeeded */
	debug(LOG_INFO, "XTCP-CLIENT: hole-punch succeeded with %s:%d",
	      inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	sess->hole_punched = 1;
	memcpy(&sess->peer_addr, &from, sizeof(from));
	nathole_sid_msg_free(&sid_msg);
	xtcp_client_enter_tunnel(sess);
}

/* ---- Send NatHoleSid probe to a specific address ---- */
static void xtcp_client_send_sid_probe(struct xtcp_client_session *sess,
					const char *addr)
{
	struct nathole_sid_msg sid_msg;
	memset(&sid_msg, 0, sizeof(sid_msg));
	sid_msg.transaction_id = sess->transaction_id;
	sid_msg.sid = sess->sid;
	sid_msg.response = false;

	/* Generate random nonce via OpenSSL */
	char nonce[32];
	unsigned char rand_buf[16];
	RAND_bytes(rand_buf, sizeof(rand_buf));
	static const char hex_chars[] = "0123456789abcdef";
	int nonce_len = rand_buf[0] % 20;
	for (int i = 0; i < nonce_len; i++)
		nonce[i] = hex_chars[rand_buf[i + 1] & 0xf];
	nonce[nonce_len] = '\0';
	sid_msg.nonce = nonce;

	uint8_t *pkt = NULL;
	size_t pkt_len = 0;
	if (nathole_encode_sid(&sid_msg, sess->ps->sk, &pkt, &pkt_len) < 0)
		return;

	struct sockaddr_in target;
	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;

	char host[256];
	strncpy(host, addr, sizeof(host) - 1);
	host[sizeof(host) - 1] = '\0';
	char *colon = strrchr(host, ':');
	if (!colon) { free(pkt); return; }
	*colon = '\0';
	int port = atoi(colon + 1);

	if (inet_pton(AF_INET, host, &target.sin_addr) != 1) {
		free(pkt);
		return;
	}
	target.sin_port = htons(port);

	/* Save and set TTL if needed */
	int saved_ttl = 0;
	socklen_t ttl_len = sizeof(saved_ttl);
	getsockopt(sess->udp_fd, IPPROTO_IP, IP_TTL, &saved_ttl, &ttl_len);

	if (sess->ttl > 0) {
		int ttl = sess->ttl;
		setsockopt(sess->udp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	}

	sendto(sess->udp_fd, pkt, pkt_len, 0,
	       (struct sockaddr *)&target, sizeof(target));

	/* Restore original TTL */
	setsockopt(sess->udp_fd, IPPROTO_IP, IP_TTL, &saved_ttl, sizeof(saved_ttl));

	debug(LOG_DEBUG, "XTCP-CLIENT: sent probe to %s:%d", host, port);
	free(pkt);
}

/* ---- Send probes to all candidate + assisted addresses ---- */
static void xtcp_client_send_sid_probe_to_all(struct xtcp_client_session *sess)
{
	debug(LOG_DEBUG, "XTCP-CLIENT: sending probes (role=%s, send_random=%d, port_ranges=%d)",
	      sess->is_sender ? "sender" : "receiver",
	      sess->send_random_ports, sess->candidate_ports_count);

	/* Send to assisted (LAN) addresses first */
	for (int i = 0; i < sess->assisted_addrs_count; i++) {
		if (sess->assisted_addrs[i])
			xtcp_client_send_sid_probe(sess, sess->assisted_addrs[i]);
	}

	/* Send to candidate (WAN) addresses */
	for (int i = 0; i < sess->candidate_addrs_count; i++) {
		if (sess->candidate_addrs[i])
			xtcp_client_send_sid_probe(sess, sess->candidate_addrs[i]);
	}

	/* Send to candidate port ranges */
	for (int r = 0; r < sess->candidate_ports_count && r < 16; r++) {
		int from_port = sess->candidate_ports_from[r];
		int to_port = sess->candidate_ports_to[r];
		if (from_port <= 0 || to_port <= 0 || from_port > to_port) continue;

		char ip[64] = {0};
		if (sess->candidate_addrs_count > 0 && sess->candidate_addrs[0]) {
			strncpy(ip, sess->candidate_addrs[0], sizeof(ip) - 1);
			char *colon = strrchr(ip, ':');
			if (colon) *colon = '\0';
		}
		if (!ip[0]) continue;

		for (int p = from_port; p <= to_port; p++) {
			char addr[128];
			snprintf(addr, sizeof(addr), "%s:%d", ip, p);
			xtcp_client_send_sid_probe(sess, addr);
		}
	}

	/* Send to random ports on peer's IP */
	if (sess->send_random_ports > 0) {
		char ip[64] = {0};
		if (sess->candidate_addrs_count > 0 && sess->candidate_addrs[0]) {
			strncpy(ip, sess->candidate_addrs[0], sizeof(ip) - 1);
			char *colon = strrchr(ip, ':');
			if (colon) *colon = '\0';
		}
		if (ip[0]) {
			int n = sess->send_random_ports;
			if (n > 1000) n = 1000;
			unsigned char rbuf[2];
			for (int i = 0; i < n; i++) {
				RAND_bytes(rbuf, 2);
				int port = 1024 + ((rbuf[0] << 8 | rbuf[1]) % (65535 - 1024));
				char addr[128];
				snprintf(addr, sizeof(addr), "%s:%d", ip, port);
				xtcp_client_send_sid_probe(sess, addr);
			}
			debug(LOG_DEBUG, "XTCP-CLIENT: sent %d random port probes", n);
		}
	}
}

/* ---- Start hole-punching ---- */
static void xtcp_client_start_make_hole(struct xtcp_client_session *sess)
{
	sess->state = XTCP_CLI_MAKE_HOLE;

	sess->udp_event = event_new(sess->base, sess->udp_fd,
				    EV_READ | EV_PERSIST,
				    xtcp_client_udp_recv_cb, sess);
	event_add(sess->udp_event, NULL);

	/* For receiver: listen on random ports if requested */
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
						     xtcp_client_udp_recv_cb, sess);
			event_add(ev, NULL);
			sess->extra_fds[sess->extra_fd_count] = fd;
			sess->extra_events[sess->extra_fd_count] = ev;
			sess->extra_fd_count++;
		}
		debug(LOG_DEBUG, "XTCP-CLIENT: listening on %d extra random ports",
		      sess->extra_fd_count);
	}

	/* Send probes based on role */
	if (sess->is_sender) {
		if (sess->send_delay_ms > 0) {
			debug(LOG_DEBUG, "XTCP-CLIENT: sender delaying %dms",
			      sess->send_delay_ms);
			struct timeval tv = {
				.tv_sec = sess->send_delay_ms / 1000,
				.tv_usec = (sess->send_delay_ms % 1000) * 1000
			};
			sess->timer_event = evtimer_new(sess->base,
							xtcp_client_send_delay_cb, sess);
			evtimer_add(sess->timer_event, &tv);
		} else {
			xtcp_client_send_sid_probe_to_all(sess);
		}
	} else {
		xtcp_client_send_sid_probe_to_all(sess);
	}
}

/* ---- QUIC callbacks ---- */
#ifdef HAVE_NGTCP2
static void client_quic_stream_recv_cb(int64_t stream_id,
					const uint8_t *data, size_t datalen,
					void *user_data)
{
	struct xtcp_client_session *sess = user_data;
	if (!sess || !sess->local_bev) return;

	struct evbuffer *output = bufferevent_get_output(sess->local_bev);
	evbuffer_add(output, data, datalen);
	debug(LOG_DEBUG, "XTCP-CLIENT-QUIC: relayed %zu bytes stream=%ld → local",
	      datalen, (long)stream_id);
}

static void client_quic_stream_close_cb(int64_t stream_id,
					 uint64_t app_error_code,
					 void *user_data)
{
	struct xtcp_client_session *sess = user_data;
	(void)stream_id; (void)app_error_code;
	debug(LOG_INFO, "XTCP-CLIENT-QUIC: stream %ld closed", (long)stream_id);
	xtcp_client_cleanup(sess);
}

static void client_quic_conn_ready_cb(void *user_data)
{
	struct xtcp_client_session *sess = user_data;
	debug(LOG_INFO, "XTCP-CLIENT-QUIC: connection ready for '%s'",
	      sess->ps->proxy_name);
	sess->state = XTCP_CLI_RELAY;
}

static void client_quic_conn_close_cb(uint64_t error_code, void *user_data)
{
	struct xtcp_client_session *sess = user_data;
	debug(LOG_INFO, "XTCP-CLIENT-QUIC: connection closed (err=%lu)",
	      (unsigned long)error_code);
	xtcp_client_cleanup(sess);
}
#endif

/* ---- Tunnel-mode UDP callback (raw relay) ---- */
static void xtcp_client_tunnel_udp_recv_cb(evutil_socket_t fd, short events, void *ctx)
{
	struct xtcp_client_session *sess = ctx;
	if (!sess) return;

	uint8_t buf[65536];
	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);

	ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
			     (struct sockaddr *)&from, &from_len);
	if (n <= 0) return;

	/* Append to per-session reassembly buffer */
	if (sess->udp_recv_len + n <= sizeof(sess->udp_recv_buf)) {
		memcpy(sess->udp_recv_buf + sess->udp_recv_len, buf, n);
		sess->udp_recv_len += n;
	}

	/* Process framed data: 2-byte length header + payload */
	while (sess->udp_recv_len >= 2) {
		uint16_t frame_len = ntohs(*(uint16_t *)sess->udp_recv_buf);
		if (frame_len == 0 || frame_len > 65535) {
			sess->udp_recv_len = 0;
			return;
		}
		if (sess->udp_recv_len < 2 + frame_len)
			break;

		if (sess->local_bev) {
			uint8_t *payload = sess->udp_recv_buf + 2;
			size_t payload_len = frame_len;

			if (sess->use_encryption && frame_len > 16) {
				uint8_t *dec_data = NULL;
				struct frp_coder decoder;
				memcpy(decoder.key, sess->encoder ? sess->encoder->key : decoder.key, 16);
				memcpy(decoder.iv, payload, 16);
				decoder.salt = NULL;
				decoder.token = NULL;

				size_t dec_len = decrypt_data(payload + 16, payload_len - 16,
							      &decoder, &dec_data);
				if (dec_len > 0 && dec_data) {
					struct evbuffer *output = bufferevent_get_output(sess->local_bev);
					evbuffer_add(output, dec_data, dec_len);
					free(dec_data);
				} else {
					debug(LOG_WARNING, "XTCP-CLIENT: decrypt failed");
				}
			} else {
				struct evbuffer *output = bufferevent_get_output(sess->local_bev);
				evbuffer_add(output, payload, payload_len);
			}
		}

		size_t consumed = 2 + frame_len;
		memmove(sess->udp_recv_buf, sess->udp_recv_buf + consumed,
			sess->udp_recv_len - consumed);
		sess->udp_recv_len -= consumed;
	}
}

/* ---- Local service connection callbacks ---- */
static void xtcp_local_read_cb(struct bufferevent *bev, void *ctx)
{
	struct xtcp_client_session *sess = ctx;
	if (!sess || sess->state != XTCP_CLI_RELAY) return;

	struct evbuffer *input = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(input);
	if (len == 0) return;

#ifdef HAVE_NGTCP2
	if (sess->quic && quic_ctx_is_ready(sess->quic)) {
		ssize_t written = quic_stream_write_evbuf(sess->quic, -1, input);
		if (written < 0) {
			debug(LOG_WARNING, "XTCP-CLIENT-QUIC: stream write failed");
		}
		return;
	}
#endif

	/* Fallback: raw UDP with framing */
	uint8_t *data = evbuffer_pullup(input, len);
	if (data && len > 0) {
		if (len > 65535) len = 65535;

		uint8_t frame[65537];
		uint16_t frame_len;
		size_t payload_len;

		if (sess->use_encryption && sess->encoder) {
			uint8_t *enc_data = NULL;
			RAND_bytes(sess->encoder->iv, 16);
			size_t enc_len = encrypt_data(data, len, sess->encoder, &enc_data);
			if (enc_len > 0 && enc_data) {
				payload_len = 16 + enc_len;
				frame_len = htons((uint16_t)payload_len);
				memcpy(frame, &frame_len, 2);
				memcpy(frame + 2, sess->encoder->iv, 16);
				memcpy(frame + 18, enc_data, enc_len);
				free(enc_data);
			} else {
				debug(LOG_WARNING, "XTCP-CLIENT: encrypt failed, sending plaintext");
				frame_len = htons((uint16_t)len);
				memcpy(frame, &frame_len, 2);
				memcpy(frame + 2, data, len);
				payload_len = len;
			}
		} else {
			frame_len = htons((uint16_t)len);
			memcpy(frame, &frame_len, 2);
			memcpy(frame + 2, data, len);
			payload_len = len;
		}

		ssize_t sent = sendto(sess->udp_fd, frame, payload_len + 2, 0,
			      (struct sockaddr *)&sess->peer_addr,
			      sizeof(sess->peer_addr));
		if (sent > 2) {
			evbuffer_drain(input, (size_t)(sent - 2));
		} else if (sent < 0) {
			debug(LOG_WARNING, "XTCP-CLIENT: sendto failed: %s",
			      strerror(errno));
		}
	}
}

static void xtcp_local_event_cb(struct bufferevent *bev, short events, void *ctx)
{
	struct xtcp_client_session *sess = ctx;
	(void)bev;
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		debug(LOG_INFO, "XTCP-CLIENT: local service connection %s",
		      (events & BEV_EVENT_EOF) ? "closed" : "error");
		xtcp_client_cleanup(sess);
	}
}

/* ---- Enter tunnel mode ---- */
static void xtcp_client_enter_tunnel(struct xtcp_client_session *sess)
{
	sess->state = XTCP_CLI_TUNNEL_EST;

	debug(LOG_INFO, "XTCP-CLIENT: P2P tunnel established with %s:%d",
	      inet_ntoa(sess->peer_addr.sin_addr), ntohs(sess->peer_addr.sin_port));

	xtcp_client_report_result(sess, 1);

	if (sess->timeout_event) {
		event_del(sess->timeout_event);
		event_free(sess->timeout_event);
		sess->timeout_event = NULL;
	}

	/* Close extra listen sockets */
	for (int i = 0; i < sess->extra_fd_count; i++) {
		if (sess->extra_events[i])
			event_free(sess->extra_events[i]);
		if (sess->extra_fds[i] >= 0)
			close(sess->extra_fds[i]);
	}
	sess->extra_fd_count = 0;

	/* Connect to local service */
	struct sockaddr_in local_addr;
	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(sess->ps->local_port);
	if (sess->ps->local_ip && sess->ps->local_ip[0]) {
		inet_pton(AF_INET, sess->ps->local_ip, &local_addr.sin_addr);
	} else {
		local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}

	sess->local_bev = bufferevent_socket_new(sess->base, -1,
						     BEV_OPT_CLOSE_ON_FREE);
	if (!sess->local_bev) {
		debug(LOG_ERR, "XTCP-CLIENT: failed to create local bev");
		xtcp_client_cleanup(sess);
		return;
	}

	if (bufferevent_socket_connect(sess->local_bev,
				       (struct sockaddr *)&local_addr,
				       sizeof(local_addr)) < 0) {
		debug(LOG_ERR, "XTCP-CLIENT: failed to connect to local service %s:%d",
		      sess->ps->local_ip ? sess->ps->local_ip : "127.0.0.1",
		      sess->ps->local_port);
		xtcp_client_cleanup(sess);
		return;
	}

	bufferevent_setcb(sess->local_bev, xtcp_local_read_cb, NULL,
			  xtcp_local_event_cb, sess);
	bufferevent_enable(sess->local_bev, EV_READ | EV_WRITE);

#ifdef HAVE_NGTCP2
	/* Try QUIC transport */
	debug(LOG_INFO, "XTCP-CLIENT: establishing QUIC transport");

	struct quic_config qcfg = {
		.alpn = "frp",
		.max_idle_timeout_sec = 60,
		.max_streams = 8,
		.is_server = 1,  /* client side is QUIC server (accepts connection) */
	};

	struct quic_stream_callbacks qcbs = {
		.on_recv = client_quic_stream_recv_cb,
		.on_close = client_quic_stream_close_cb,
		.on_conn_ready = client_quic_conn_ready_cb,
		.on_conn_close = client_quic_conn_close_cb,
		.user_data = sess,
	};

	sess->quic = quic_ctx_new(sess->base, sess->udp_fd,
				  &sess->peer_addr, &qcfg, &qcbs);
	if (!sess->quic) {
		debug(LOG_WARNING, "XTCP-CLIENT: QUIC setup failed, using raw UDP");
	} else {
		if (sess->udp_event) {
			event_del(sess->udp_event);
			event_free(sess->udp_event);
			sess->udp_event = NULL;
		}
		debug(LOG_INFO, "XTCP-CLIENT: QUIC transport active");
		return;
	}
#endif

	/* Fallback: raw UDP relay */
	debug(LOG_WARNING, "XTCP-CLIENT: using raw UDP relay");

	/* Initialize tunnel encryption if configured */
	if (sess->ps && sess->ps->use_encryption && sess->secret_key) {
		sess->encoder = new_coder(sess->secret_key, "xtcp-tunnel");
		sess->decoder = NULL;
		sess->use_encryption = 1;
		debug(LOG_INFO, "XTCP-CLIENT: tunnel encryption enabled (AES-128-CFB)");
	}

	if (sess->udp_event) {
		event_del(sess->udp_event);
		event_free(sess->udp_event);
		sess->udp_event = NULL;
	}

	sess->udp_event = event_new(sess->base, sess->udp_fd,
				    EV_READ | EV_PERSIST,
				    xtcp_client_tunnel_udp_recv_cb, sess);
	event_add(sess->udp_event, NULL);

	sess->state = XTCP_CLI_RELAY;
	debug(LOG_INFO, "XTCP-CLIENT: raw UDP relay active for '%s'",
	      sess->ps->proxy_name);
}

/* ---- Report result to server ---- */
static void xtcp_client_report_result(struct xtcp_client_session *sess, int success)
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
			send_msg_frp_server(ctl->connect_bev, TypeNatHoleReport,
					    json_str, json_len, &ctl->stream);
		}
		free(json_str);
	}
}

/* ---- Cleanup ---- */
static void xtcp_client_cleanup(struct xtcp_client_session *sess)
{
	if (!sess) return;

	xtcp_client_session_unregister(sess);

#ifdef HAVE_NGTCP2
	if (sess->quic) {
		quic_ctx_free(sess->quic);
		sess->quic = NULL;
	}
#endif

	if (sess->local_bev) {
		bufferevent_free(sess->local_bev);
		sess->local_bev = NULL;
	}

	if (sess->udp_event) {
		event_del(sess->udp_event);
		event_free(sess->udp_event);
		sess->udp_event = NULL;
	}

	if (sess->timeout_event) {
		event_del(sess->timeout_event);
		event_free(sess->timeout_event);
		sess->timeout_event = NULL;
	}

	if (sess->timer_event) {
		event_del(sess->timer_event);
		event_free(sess->timer_event);
		sess->timer_event = NULL;
	}

	for (int i = 0; i < sess->extra_fd_count; i++) {
		if (sess->extra_events[i])
			event_free(sess->extra_events[i]);
		if (sess->extra_fds[i] >= 0)
			close(sess->extra_fds[i]);
	}

	if (sess->udp_fd >= 0) {
		close(sess->udp_fd);
		sess->udp_fd = -1;
	}

	for (int i = 0; i < sess->candidate_addrs_count; i++)
		free(sess->candidate_addrs[i]);
	for (int i = 0; i < sess->assisted_addrs_count; i++)
		free(sess->assisted_addrs[i]);

	if (sess->encoder) free(sess->encoder);
	if (sess->decoder) free(sess->decoder);
	if (sess->secret_key) free(sess->secret_key);

	free(sess);
}

/* ---- Start exchange: send NatHoleClient to server ---- */
static void xtcp_client_start_exchange(struct xtcp_client_session *sess)
{
	debug(LOG_DEBUG, "XTCP-CLIENT: sending NatHoleClient for '%s'",
	      sess->ps->proxy_name);
	if (send_nathole_client(sess) < 0) {
		debug(LOG_ERR, "XTCP-CLIENT: NatHoleClient send failed");
		xtcp_client_cleanup(sess);
	}
}

/* ---- Entry point: called from handle_type_start_work_conn ---- */
void xtcp_client_run(struct event_base *base, struct proxy_client *client)
{
	if (!base || !client || !client->ps) return;

	struct proxy_service *ps = client->ps;
	debug(LOG_INFO, "XTCP-CLIENT: starting XTCP client for proxy '%s'",
	      ps->proxy_name);

	struct xtcp_client_session *sess = calloc(1, sizeof(*sess));
	if (!sess) return;

	sess->base = base;
	sess->client = client;
	sess->ps = ps;
	sess->udp_fd = -1;
	sess->state = XTCP_CLI_STUN;

	/* Initialize encryption key from auth_token if use_encryption is set */
	if (ps->use_encryption) {
		struct common_conf *cc = get_common_config();
		if (cc && cc->auth_token) {
			sess->secret_key = strdup(cc->auth_token);
		}
	}

#ifdef HAVE_NGTCP2
	sess->quic = NULL;
#endif

	/* Generate transaction ID */
	nathole_gen_transaction_id(sess->transaction_id, sizeof(sess->transaction_id));

	/* Register for NatHoleResp dispatching */
	xtcp_client_session_register(sess);

	/* Set overall timeout */
	struct timeval tv = { .tv_sec = CLIENT_TIMEOUT_SEC, .tv_usec = 0 };
	sess->timeout_event = evtimer_new(base, xtcp_client_timeout_cb, sess);
	evtimer_add(sess->timeout_event, &tv);

	/* Check STUN cache */
	struct xtcp_client_stun_cache *cache = NULL;
	for (int i = 0; i < client_stun_cache_count; i++) {
		if (strcmp(client_stun_cache[i].proxy_name, ps->proxy_name) == 0) {
			cache = &client_stun_cache[i];
			break;
		}
	}
	if (!cache && client_stun_cache_count < MAX_CACHED_PROXIES) {
		cache = &client_stun_cache[client_stun_cache_count++];
		strncpy(cache->proxy_name, ps->proxy_name, sizeof(cache->proxy_name) - 1);
	}

	if (cache && cache->valid) {
		debug(LOG_DEBUG, "XTCP-CLIENT: using cached STUN result");
		/* Still need a UDP socket for hole-punching */
		sess->udp_fd = cache->udp_fd;
		cache->udp_fd = -1; /* Transfer ownership */
		xtcp_client_start_exchange(sess);
		return;
	}

	/* Do STUN discovery */
	int stun_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (stun_fd < 0) {
		debug(LOG_ERR, "XTCP-CLIENT: socket() failed: %s", strerror(errno));
		xtcp_client_cleanup(sess);
		return;
	}
	evutil_make_socket_nonblocking(stun_fd);

	struct stun_result sresult;
	const char *servers[8];
	int scount = 0;
	for (int i = 0; default_stun_servers[i] && scount < 7; i++)
		servers[scount++] = default_stun_servers[i];
	servers[scount] = NULL;

	if (stun_discover_on_socket(stun_fd, servers, &sresult) < 0 ||
	    sresult.addr_count < 2) {
		debug(LOG_ERR, "XTCP-CLIENT: STUN discovery failed (need 2+ addresses)");
		close(stun_fd);
		xtcp_client_cleanup(sess);
		return;
	}

	debug(LOG_INFO, "XTCP-CLIENT: STUN discovered %d addresses", sresult.addr_count);

	/* Cache results */
	if (cache) {
		for (int i = 0; i < sresult.addr_count && i < MAX_MAPPED_ADDRS; i++)
			strncpy(cache->mapped_addrs[i], sresult.addrs[i].addr, 63);
		cache->mapped_addrs_count = sresult.addr_count;

		char local_ip[64];
		inet_ntop(AF_INET, &sresult.local_addr.sin_addr,
			  local_ip, sizeof(local_ip));
		snprintf(cache->local_addr, sizeof(cache->local_addr),
			 "%d", ntohs(sresult.local_addr.sin_port));

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
			debug(LOG_INFO, "XTCP-CLIENT: NAT type=%s, behavior=%s",
			      cache->nat_feat.nat_type, cache->nat_feat.behavior);
		}

		cache->udp_fd = stun_fd;
		cache->valid = 1;
		sess->udp_fd = stun_fd; /* Keep for this session */
		cache->udp_fd = -1;     /* Transfer ownership */
	} else {
		sess->udp_fd = stun_fd;
	}

	xtcp_client_start_exchange(sess);
}

/* ---- Handle NatHoleResp for client sessions ---- */
int xtcp_client_handle_nat_hole_resp(const char *json_str)
{
	if (!json_str) return 0;

	struct nathole_resp_msg *resp = nathole_resp_unmarshal(json_str);
	if (!resp) return 0;

	debug(LOG_DEBUG, "XTCP-CLIENT: NatHoleResp received, sid=%s, transaction_id=%s",
	      resp->sid ? resp->sid : "",
	      resp->transaction_id ? resp->transaction_id : "");

	/* Find matching session by transaction_id */
	struct xtcp_client_session *sess = NULL;
	for (int i = 0; i < active_client_count; i++) {
		if (active_client_sessions[i]->transaction_id[0] &&
		    resp->transaction_id &&
		    strcmp(active_client_sessions[i]->transaction_id,
			   resp->transaction_id) == 0) {
			sess = active_client_sessions[i];
			break;
		}
	}

	if (!sess) {
		nathole_resp_msg_free(resp);
		return 0; /* Not for us */
	}

	xtcp_client_handle_nat_hole_resp_impl(sess, resp);
	nathole_resp_msg_free(resp);
	return 1; /* Handled */
}

/* ---- Process NatHoleResp ---- */
static void xtcp_client_handle_nat_hole_resp_impl(struct xtcp_client_session *sess,
						   struct nathole_resp_msg *resp)
{
	if (!sess || !resp) return;

	if (resp->error && strlen(resp->error) > 0) {
		debug(LOG_ERR, "XTCP-CLIENT: NatHoleResp error: %s", resp->error);
		xtcp_client_cleanup(sess);
		return;
	}

	/* Store session ID */
	strncpy(sess->sid, resp->sid ? resp->sid : "", sizeof(sess->sid) - 1);

	/* Store candidate and assisted addresses */
	for (int i = 0; i < resp->candidate_addrs_count && i < MAX_CANDIDATE_ADDRS; i++)
		sess->candidate_addrs[i] = strdup(resp->candidate_addrs[i]);
	sess->candidate_addrs_count = resp->candidate_addrs_count;

	for (int i = 0; i < resp->assisted_addrs_count && i < MAX_CANDIDATE_ADDRS; i++)
		sess->assisted_addrs[i] = strdup(resp->assisted_addrs[i]);
	sess->assisted_addrs_count = resp->assisted_addrs_count;

	/* Parse detect behavior */
	sess->is_sender = (resp->behavior_role &&
			   strcmp(resp->behavior_role, "sender") == 0);
	sess->send_delay_ms = resp->behavior_send_delay_ms;
	sess->read_timeout_ms = resp->behavior_read_timeout_ms;
	sess->ttl = resp->behavior_ttl;
	sess->send_random_ports = resp->behavior_send_random_ports;
	sess->listen_random_ports = resp->behavior_listen_random_ports;

	/* Store candidate port ranges */
	sess->candidate_ports_count = resp->candidate_ports_count;
	for (int i = 0; i < resp->candidate_ports_count && i < 16; i++) {
		sess->candidate_ports_from[i] = resp->candidate_ports_from[i];
		sess->candidate_ports_to[i] = resp->candidate_ports_to[i];
	}

	debug(LOG_INFO, "XTCP-CLIENT: NatHoleResp sid=%s, role=%s, candidates=%d, assisted=%d, send_random=%d, port_ranges=%d",
	      sess->sid,
	      sess->is_sender ? "sender" : "receiver",
	      resp->candidate_addrs_count,
	      resp->assisted_addrs_count);

	/* Ensure we have a UDP socket */
	if (sess->udp_fd < 0) {
		sess->udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sess->udp_fd < 0) {
			debug(LOG_ERR, "XTCP-CLIENT: socket() failed: %s", strerror(errno));
			xtcp_client_cleanup(sess);
			return;
		}
		struct sockaddr_in bind_addr;
		memset(&bind_addr, 0, sizeof(bind_addr));
		bind_addr.sin_family = AF_INET;
		bind(sess->udp_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
	}
	evutil_make_socket_nonblocking(sess->udp_fd);

	/* Reset timeout to server-provided read_timeout_ms for hole-punch phase */
	if (sess->timeout_event && sess->read_timeout_ms > 0) {
		event_del(sess->timeout_event);
		struct timeval tv = {
			.tv_sec = sess->read_timeout_ms / 1000,
			.tv_usec = (sess->read_timeout_ms % 1000) * 1000
		};
		evtimer_add(sess->timeout_event, &tv);
		debug(LOG_DEBUG, "XTCP-CLIENT: hole-punch timeout set to %dms",
		      sess->read_timeout_ms);
	}

	debug(LOG_DEBUG, "XTCP-CLIENT: UDP socket ready (fd=%d), starting hole-punch",
	      sess->udp_fd);

	xtcp_client_start_make_hole(sess);
}

/* ---- Cleanup all client sessions ---- */
void cleanup_xtcp_clients(void)
{
	for (int i = active_client_count - 1; i >= 0; i--) {
		xtcp_client_cleanup(active_client_sessions[i]);
	}
	active_client_count = 0;

	for (int i = 0; i < client_stun_cache_count; i++) {
		if (client_stun_cache[i].udp_fd >= 0) {
			close(client_stun_cache[i].udp_fd);
			client_stun_cache[i].udp_fd = -1;
		}
	}
	client_stun_cache_count = 0;
}
