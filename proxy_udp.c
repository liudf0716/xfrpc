
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <sys/socket.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>

#include "debug.h"
#include "uthash.h"
#include "common.h"
#include "proxy.h"
#include "config.h"
#include "tcpmux.h"
#include "control.h"
#include "wire_v2.h"

// Base64 encoding table
static const char BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Encode binary data using base64 encoding
 * @param src Input binary data
 * @param srclen Length of input data
 * @param dst Output buffer for base64 encoded string
 * @return Length of encoded string or -1 on error
 */
static int base64_encode(const uint8_t *src, int srclen, char *dst) 
{
    if (!src || !dst || srclen < 0) return -1;
    
    uint32_t bits_buf = 0;
    int bits_cnt = 0;
    char *out = dst;

    while (srclen--) {
        bits_buf = (bits_buf << 8) | *src++;
        bits_cnt += 8;

        while (bits_cnt >= 6) {
            bits_cnt -= 6;
            *out++ = BASE64_CHARS[(bits_buf >> bits_cnt) & 0x3f];
        }
    }

    // Handle remaining bits
    if (bits_cnt > 0) {
        *out++ = BASE64_CHARS[(bits_buf << (6 - bits_cnt)) & 0x3f];
        
        // Add padding
        while (bits_cnt < 6) {
            *out++ = '=';
            bits_cnt += 2;
        }
    }

    return out - dst;
}

/**
 * Decode base64 encoded string to binary data
 * @param src Input base64 encoded string
 * @param srclen Length of input string
 * @param dst Output buffer for decoded data
 * @return Length of decoded data or -1 on error
 */
static int base64_decode(const char *src, int srclen, uint8_t *dst)
{
    if (!src || !dst || srclen < 0) return -1;

    uint32_t bits_buf = 0;
    int bits_cnt = 0;
    uint8_t *out = dst;

    while (srclen--) {
        char c = *src++;
        
        if (c == '=') {
            bits_buf <<= 6;
            bits_cnt += 6;
            continue;
        }

        const char *p = strchr(BASE64_CHARS, c);
        if (!p) return -1;  // Invalid character

        bits_buf = (bits_buf << 6) | (p - BASE64_CHARS);
        bits_cnt += 6;

        if (bits_cnt >= 8) {
            bits_cnt -= 8;
            *out++ = (bits_buf >> bits_cnt) & 0xff;
        }
    }

    // Check for invalid trailing bits
    if (bits_buf & ((1 << bits_cnt) - 1)) {
        return -1;
    }

    return out - dst;
}

#define UDP_MAX_PACKET_SIZE 1500
#define BASE64_ENCODE_SIZE(x) ((((x) + 2) / 3) * 4 + 1)

/**
 * @brief Decodes base64 encoded data from a source buffer to a destination buffer
 *
 * @param src Source evbuffer containing the base64 encoded data
 * @param dst Destination evbuffer where the decoded data will be stored
 * @return int Returns 0 on success, -1 on failure
 */
static int evutil_base64_decode(struct evbuffer *src, struct evbuffer *dst)
{
    if (!src || !dst) return -1;

    size_t src_len = evbuffer_get_length(src);
    if (src_len == 0) return 0;

    char *src_buf = malloc(src_len);
    if (!src_buf) return -1;

    uint8_t *decode_buf = malloc(src_len); // Base64 decode is always smaller than input
    if (!decode_buf) {
        free(src_buf);
        return -1;
    }

    evbuffer_remove(src, src_buf, src_len);
    int decode_len = base64_decode(src_buf, src_len, decode_buf);
    
    if (decode_len > 0 && decode_len <= UDP_MAX_PACKET_SIZE) {
        evbuffer_add(dst, decode_buf, decode_len);
    }

    free(src_buf);
    free(decode_buf);
    
    return decode_len;
}

/**
 * @brief Encodes data from a source buffer to base64 format in a destination buffer
 *
 * @param src Source evbuffer containing data to be encoded
 * @param dst Destination evbuffer where the base64 encoded data will be stored
 * @return int Returns 0 on success, -1 on failure
 *
 * This function takes the contents of the source evbuffer, performs base64 encoding
 * on the data, and stores the resulting encoded data in the destination evbuffer.
 * The function uses the libevent evbuffer structure for buffer management.
 */
static int evutil_base64_encode(struct evbuffer *src, struct evbuffer *dst)
{
    if (!src || !dst) return -1;

    size_t src_len = evbuffer_get_length(src);
    if (src_len == 0) return 0;
    if (src_len > UDP_MAX_PACKET_SIZE) return -1;

    uint8_t *src_buf = malloc(src_len);
    if (!src_buf) return -1;

    size_t encode_buf_len = BASE64_ENCODE_SIZE(src_len);
    char *encode_buf = malloc(encode_buf_len);
    if (!encode_buf) {
        free(src_buf);
        return -1;
    }

    evbuffer_remove(src, src_buf, src_len);
    int encode_len = base64_encode(src_buf, src_len, encode_buf);
    
    if (encode_len > 0) {
        evbuffer_add(dst, encode_buf, encode_len);
    }

    free(src_buf);
    free(encode_buf);
    
    return encode_len;
}

int resolve_local_addr(const char *ip, struct sockaddr_in *addr) {
    if (!ip || !addr) return -1;
    if (inet_pton(AF_INET, ip, &addr->sin_addr) > 0) {
        return 0;
    }

    struct hostent *host = gethostbyname(ip);
    if (!host) {
        debug(LOG_ERR, "Failed to resolve hostname: %s", ip);
        return -1;
    }

    memcpy(&addr->sin_addr, host->h_addr, host->h_length);
    return 0;
}

#define MAX_UDP_SESSIONS 128
#define UDP_SESSION_TIMEOUT 120

static void free_udp_session(struct proxy_client *client, struct udp_session *sess)
{
    if (!sess) return;
    if (client && client->udp_sessions) {
        HASH_DEL(client->udp_sessions, sess);
    }
    if (sess->bev) {
        bufferevent_free(sess->bev);
        sess->bev = NULL;
    }
    SAFE_FREE(sess->raddr);
    SAFE_FREE(sess->rzone);
    SAFE_FREE(sess->laddr);
    SAFE_FREE(sess->lzone);
    free(sess);
}

void clear_udp_sessions(struct proxy_client *client)
{
    if (!client || !client->udp_sessions)
        return;

    struct udp_session *cur, *tmp;
    HASH_ITER(hh, client->udp_sessions, cur, tmp) {
        free_udp_session(client, cur);
    }
    client->udp_sessions = NULL;
}

static void send_udp_packet_to_server(struct proxy_client *client, const char *json_buf, size_t json_len)
{
    struct common_conf *c_conf = get_common_config();
    if (client->use_encryption || client->use_compression) {
        struct evbuffer *raw = evbuffer_new();
        struct evbuffer *processed = evbuffer_new();
        if (raw && processed) {
            struct msg_hdr *req_msg = NULL;
            size_t total_len = 0;
            if (prepare_message(TypeUDPPacket, json_buf, json_len, &req_msg, &total_len) == 0) {
                evbuffer_add(raw, req_msg, total_len);
                free(req_msg);

                if (client->enc_pending && evbuffer_get_length(client->enc_pending) > 0)
                    evbuffer_add_buffer(processed, client->enc_pending);

                proxy_crypto_encode_evbuffer(client, raw, processed);

                if (!c_conf->tcp_mux) {
                    struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
                    evbuffer_add_buffer(dst, processed);
                } else {
                    while (evbuffer_get_length(processed) > 0) {
                        int written = tmux_stream_write(client->ctl_bev, processed, &client->stream);
                        if (written < 0) {
                            debug(LOG_INFO, "Stream %u: tmux_stream_write error %d",
                                  client->stream.id, written);
                            del_proxy_client_by_stream_id(client->stream.id);
                            break;
                        }
                        if (written == 0) {
                            if (!client->enc_pending)
                                client->enc_pending = evbuffer_new();
                            if (client->enc_pending) {
                                evbuffer_add_buffer(client->enc_pending, processed);
                            }
                            break;
                        }
                    }
                }
            }
            evbuffer_free(raw);
            evbuffer_free(processed);
        } else {
            if (raw) evbuffer_free(raw);
            if (processed) evbuffer_free(processed);
        }
    } else {
        send_msg_frp_server(client->ctl_bev, TypeUDPPacket, json_buf, json_len,
                            &client->stream);
    }
}

static void udp_session_c2s_cb(struct bufferevent *bev, void *ctx)
{
    struct udp_session *sess = (struct udp_session *)ctx;
    if (!sess || !sess->client || !sess->client->ctl_bev)
        return;

    struct proxy_client *client = sess->client;
    sess->last_active = time(NULL);

    struct evbuffer *src = bufferevent_get_input(bev);
    if (evbuffer_get_length(src) == 0)
        return;

    struct evbuffer *base64_output = evbuffer_new();
    if (!base64_output) return;

    if (evutil_base64_encode(src, base64_output) < 0) {
        debug(LOG_ERR, "Base64 encoding failed for UDP session response");
        evbuffer_free(base64_output);
        return;
    }

    struct udp_packet *udp_pkt = calloc(1, sizeof(struct udp_packet));
    struct udp_addr *raddr = calloc(1, sizeof(struct udp_addr));
    if (!udp_pkt || !raddr) {
        debug(LOG_ERR, "Memory allocation failed for UDP session packet");
        if (udp_pkt) free(udp_pkt);
        if (raddr) free(raddr);
        evbuffer_free(base64_output);
        return;
    }

    evbuffer_add(base64_output, "", 1);
    udp_pkt->content = (char *)evbuffer_pullup(base64_output, -1);
    udp_pkt->raddr = raddr;
    raddr->addr = sess->raddr;
    raddr->port = sess->rport;
    raddr->zone = sess->rzone;

    if (sess->laddr) {
        struct udp_addr *laddr = calloc(1, sizeof(struct udp_addr));
        if (laddr) {
            laddr->addr = sess->laddr;
            laddr->port = sess->lport;
            laddr->zone = sess->lzone;
            udp_pkt->laddr = laddr;
        }
    }

    char *json_buf = NULL;
    if (new_udp_packet_marshal(udp_pkt, &json_buf) >= 0 && json_buf) {
        size_t json_len = strlen(json_buf);
        send_udp_packet_to_server(client, json_buf, json_len);
        free(json_buf);
    }

    free(udp_pkt->laddr);
    free(raddr);
    free(udp_pkt);
    evbuffer_free(base64_output);
}

static void udp_session_event_cb(struct bufferevent *bev, short what, void *ctx)
{
    (void)bev;
    struct udp_session *sess = (struct udp_session *)ctx;
    if (!sess || !sess->client) return;
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        debug(LOG_DEBUG, "UDP session %s closed/error (what=0x%x), removing", sess->key, what);
        free_udp_session(sess->client, sess);
    }
}

/**
 * @brief Handles incoming UDP packets for proxying
 * 
 * This function processes UDP packets received from a client and handles the UDP proxy
 * protocol logic for forwarding the packet to its destination.
 * 
 * @param udp_pkt Pointer to the UDP packet structure containing packet data
 * @param client Pointer to the proxy client structure representing the connected client
 * 
 * @note The function assumes both parameters are valid non-NULL pointers
 */
void handle_udp_packet(struct udp_packet *udp_pkt, struct proxy_client *client) {
    if (!udp_pkt || !client || !client->ps || !udp_pkt->content) {
        debug(LOG_ERR, "Invalid parameters in handle_udp_packet");
        return;
    }

    // Decode base64 content
    struct evbuffer *base64_input = evbuffer_new();
    struct evbuffer *decoded_output = evbuffer_new();
    if (!base64_input || !decoded_output) {
        debug(LOG_ERR, "Failed to create evbuffers");
        if (base64_input) evbuffer_free(base64_input);
        if (decoded_output) evbuffer_free(decoded_output);
        return;
    }

    size_t content_len = strlen(udp_pkt->content);
    if (evbuffer_add(base64_input, udp_pkt->content, content_len) != 0 ||
        evutil_base64_decode(base64_input, decoded_output) < 0) {
        debug(LOG_ERR, "Base64 decoding failed in handle_udp_packet");
        evbuffer_free(base64_input);
        evbuffer_free(decoded_output);
        return;
    }

    size_t out_len = evbuffer_get_length(decoded_output);
    unsigned char *payload = out_len > 0 ? evbuffer_pullup(decoded_output, out_len) : NULL;

    const char *r_ip = (udp_pkt->raddr && udp_pkt->raddr->addr) ? udp_pkt->raddr->addr : NULL;
    int r_port = udp_pkt->raddr ? udp_pkt->raddr->port : 0;

    if (r_ip && r_port > 0) {
        char key[64];
        snprintf(key, sizeof(key), "%s:%d", r_ip, r_port);

        struct udp_session *sess = NULL;
        HASH_FIND_STR(client->udp_sessions, key, sess);

        if (!sess) {
            /* Prune stale sessions if limit reached */
            if (HASH_COUNT(client->udp_sessions) >= MAX_UDP_SESSIONS) {
                time_t now = time(NULL);
                struct udp_session *s, *stmp;
                HASH_ITER(hh, client->udp_sessions, s, stmp) {
                    if (now - s->last_active > UDP_SESSION_TIMEOUT) {
                        free_udp_session(client, s);
                    }
                }
                /* If still at limit, evict the first */
                if (HASH_COUNT(client->udp_sessions) >= MAX_UDP_SESSIONS) {
                    s = client->udp_sessions;
                    free_udp_session(client, s);
                }
            }

            /* Create session only if local address is resolved and socket connected successfully */
            if (client->udp_local_addr_valid) {
                struct bufferevent *bev = connect_udp_server(client->base);
                if (bev) {
                    evutil_socket_t fd = bufferevent_getfd(bev);
                    if (fd >= 0 && connect(fd, (struct sockaddr *)&client->udp_local_addr,
                                           sizeof(client->udp_local_addr)) == 0) {
                        char *raddr_copy = strdup(r_ip);
                        if (raddr_copy) {
                            sess = calloc(1, sizeof(struct udp_session));
                            if (sess) {
                                strncpy(sess->key, key, sizeof(sess->key) - 1);
                                sess->raddr = raddr_copy;
                                sess->rport = r_port;
                                sess->rzone = (udp_pkt->raddr && udp_pkt->raddr->zone) ? strdup(udp_pkt->raddr->zone) : NULL;
                                if (udp_pkt->laddr && udp_pkt->laddr->addr) {
                                    sess->laddr = strdup(udp_pkt->laddr->addr);
                                    sess->lport = udp_pkt->laddr->port;
                                    sess->lzone = udp_pkt->laddr->zone ? strdup(udp_pkt->laddr->zone) : NULL;
                                }
                                sess->client = client;
                                sess->last_active = time(NULL);
                                sess->bev = bev;
                                bufferevent_setcb(sess->bev, udp_session_c2s_cb, NULL, udp_session_event_cb, sess);
                                bufferevent_enable(sess->bev, EV_READ | EV_WRITE);
                                HASH_ADD_STR(client->udp_sessions, key, sess);
                            } else {
                                free(raddr_copy);
                                bufferevent_free(bev);
                            }
                        } else {
                            bufferevent_free(bev);
                        }
                    } else {
                        debug(LOG_ERR, "connect() to local UDP server failed: %s", strerror(errno));
                        bufferevent_free(bev);
                    }
                }
            }
        }

        if (sess && sess->bev && payload && out_len > 0) {
            sess->last_active = time(NULL);
            evutil_socket_t fd = bufferevent_getfd(sess->bev);
            if (fd >= 0) {
                ssize_t n = send(fd, payload, out_len, 0);
                if (n < 0) {
                    debug(LOG_ERR, "UDP send to local (session %s) failed: %s", key, strerror(errno));
                }
            }
        }
    } else if (client->local_proxy_bev && payload && out_len > 0) {
        /* Fallback for packets without valid raddr */
        evutil_socket_t fd = bufferevent_getfd(client->local_proxy_bev);
        if (fd >= 0) {
            ssize_t n = send(fd, payload, out_len, 0);
            if (n < 0) {
                debug(LOG_ERR, "UDP send to local fallback failed: %s", strerror(errno));
            }
        }
    }

    evbuffer_free(base64_input);
    evbuffer_free(decoded_output);
}

/**
 * @brief Callback function for handling UDP proxy client-to-server data transfer
 */
void udp_proxy_c2s_cb(struct bufferevent *bev, void *ctx)
{
    struct proxy_client *client = (struct proxy_client *)ctx;
    if (!client || !client->ctl_bev || !client->ps) {
        debug(LOG_ERR, "Invalid client parameters in udp_proxy_c2s_cb");
        return;
    }

    char *json_buf = NULL;
    struct evbuffer *src = bufferevent_get_input(bev);
    struct evbuffer *base64_output = evbuffer_new();
    if (!base64_output) {
        debug(LOG_ERR, "Failed to create base64 output buffer");
        return;
    }

    // Encode data to base64
    if (evutil_base64_encode(src, base64_output) < 0) {
        debug(LOG_ERR, "Base64 encoding failed in udp_proxy_c2s_cb");
        evbuffer_free(base64_output);
        return;
    }

    // Create and populate UDP packet structure
    struct udp_packet *udp_pkt = calloc(1, sizeof(struct udp_packet));
    struct udp_addr *raddr = calloc(1, sizeof(struct udp_addr));
    if (!udp_pkt || !raddr) {
        debug(LOG_ERR, "Memory allocation failed");
        goto cleanup;
    }

    /* json-c needs a C string; base64 output is not NUL-terminated */
    evbuffer_add(base64_output, "", 1);
    udp_pkt->content = (char *)evbuffer_pullup(base64_output, -1);
    udp_pkt->raddr = raddr;
    if (client->udp_raddr) {
        raddr->addr = client->udp_raddr;
        raddr->port = client->udp_rport;
        raddr->zone = client->udp_rzone;
    } else {
        raddr->addr = client->ps->local_ip;
        raddr->port = client->ps->local_port;
    }
    if (client->udp_laddr) {
        struct udp_addr *laddr = calloc(1, sizeof(struct udp_addr));
        if (laddr) {
            laddr->addr = client->udp_laddr;
            laddr->port = client->udp_lport;
            laddr->zone = client->udp_lzone;
            udp_pkt->laddr = laddr;
        }
    }

    // Marshal UDP packet to JSON
    if (new_udp_packet_marshal(udp_pkt, &json_buf) < 0 || !json_buf) {
        debug(LOG_ERR, "UDP packet marshalling failed");
        goto cleanup;
    }

    size_t json_len = strlen(json_buf);
    send_udp_packet_to_server(client, json_buf, json_len);

cleanup:
    free(json_buf);
    free(udp_pkt->laddr);
    udp_pkt->laddr = NULL;
    free(raddr);
    udp_pkt->raddr = NULL;
    free(udp_pkt);
    evbuffer_free(base64_output);
}

void process_udp_rx_buf(struct proxy_client *client)
{
    if (!client || !client->udp_rx_buf)
        return;

    while (1) {
        size_t len = evbuffer_get_length(client->udp_rx_buf);
        if (len == 0)
            break;

        if (wire_protocol_is_v2()) {
            if (len < 8)
                break;
            uint8_t *raw = evbuffer_pullup(client->udp_rx_buf, len);
            if (!raw)
                break;
            uint16_t type = 0;
            const uint8_t *pl = NULL;
            uint32_t plen = 0;
            int n = wire_v2_parse_frame(raw, len, &type, &pl, &plen);
            if (n == 0) {
                /* Incomplete frame, wait for more data */
                break;
            }
            if (n < 0) {
                debug(LOG_ERR, "v2 invalid frame in UDP stream, draining");
                evbuffer_drain(client->udp_rx_buf, len);
                break;
            }
            if (type == WIRE_V2_FRAME_MESSAGE) {
                uint8_t *v1 = NULL;
                size_t v1_len = 0;
                if (wire_v2_payload_to_v1(pl, plen, &v1, &v1_len) == 0 && v1) {
                    if (v1_len >= sizeof(struct msg_hdr)) {
                        struct msg_hdr *mh = (struct msg_hdr *)v1;
                        if (mh->type == TypeUDPPacket) {
                            handle_type_udp_packet(mh, client);
                        }
                    }
                    free(v1);
                }
            }
            evbuffer_drain(client->udp_rx_buf, (size_t)n);
        } else {
            if (len < sizeof(struct msg_hdr))
                break;
            struct msg_hdr hdr;
            evbuffer_copyout(client->udp_rx_buf, &hdr, sizeof(hdr));
            uint64_t msg_len = msg_hton(hdr.length);
            if (msg_len > 10 * 1024 * 1024) {
                debug(LOG_ERR, "UDP message payload too large (%llu), dropping buffer",
                      (unsigned long long)msg_len);
                evbuffer_drain(client->udp_rx_buf, len);
                break;
            }
            if (len < sizeof(struct msg_hdr) + msg_len) {
                /* Incomplete message, wait for more data */
                break;
            }
            size_t total = sizeof(struct msg_hdr) + (size_t)msg_len;
            uint8_t *msg_buf = malloc(total);
            if (!msg_buf) {
                debug(LOG_ERR, "Failed to allocate memory for UDP message (%zu bytes)", total);
                break;
            }
            evbuffer_remove(client->udp_rx_buf, msg_buf, total);
            struct msg_hdr *msg = (struct msg_hdr *)msg_buf;
            if (msg->type == TypeUDPPacket) {
                handle_type_udp_packet(msg, client);
            } else {
                debug(LOG_WARNING, "Unexpected message type 0x%02x in UDP stream", (unsigned char)msg->type);
            }
            free(msg_buf);
        }
    }
}

/**
 * @brief Callback function for handling data from server to client in UDP proxy (non-mux)
 */
void udp_proxy_s2c_cb(struct bufferevent *bev, void *ctx)
{
    struct proxy_client *client = (struct proxy_client *)ctx;
    if (!client) {
        debug(LOG_ERR, "Invalid client parameters in udp_proxy_s2c_cb");
        return;
    }

    struct evbuffer *src = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(src);
    if (len == 0)
        return;

    if (!client->udp_rx_buf) {
        client->udp_rx_buf = evbuffer_new();
        if (!client->udp_rx_buf) {
            debug(LOG_ERR, "Failed to allocate udp_rx_buf");
            return;
        }
    }

    if (client->use_encryption || client->use_compression) {
        struct evbuffer *plain = evbuffer_new();
        if (!plain) {
            debug(LOG_ERR, "Failed to allocate buffer for decrypted UDP packet");
            return;
        }
        proxy_crypto_decode_evbuffer(client, src, plain);
        if (evbuffer_get_length(plain) > 0) {
            evbuffer_add_buffer(client->udp_rx_buf, plain);
            process_udp_rx_buf(client);
        }
        evbuffer_free(plain);
        return;
    }

    evbuffer_add_buffer(client->udp_rx_buf, src);
    process_udp_rx_buf(client);
}