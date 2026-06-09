// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * NAT Hole Punching module for XTCP P2P traversal.
 * Implements STUN discovery, NAT classification, and UDP hole-punch protocol.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "nathole.h"
#include "msg.h"
#include "common.h"
#include "debug.h"
#include "fastpbkdf2.h"

/* ============================================================
 * Internal helpers
 * ============================================================ */

/* Generate a random hex string for nonce */
static void random_hex(char *out, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	for (size_t i = 0; i < len; i++)
		out[i] = hex[rand() & 0xf];
	out[len] = '\0';
}

/* ============================================================
 * Transaction ID
 * ============================================================ */

void nathole_gen_transaction_id(char *buf, size_t buf_len)
{
	time_t now = time(NULL);
	char rand_hex[17];
	random_hex(rand_hex, 16);
	snprintf(buf, buf_len, "%ld%s", (long)now, rand_hex);
}

/* ============================================================
 * Auth Key: MD5(secret_key + timestamp_string)
 * ============================================================ */

int nathole_auth_key(const char *secret_key, time_t timestamp, char **out_key)
{
	if (!secret_key || !out_key) return -1;

	char seed[256];
	snprintf(seed, sizeof(seed), "%s%ld", secret_key, (long)timestamp);
	size_t seed_len = strlen(seed);

	uint8_t digest[16];
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) return -1;
	if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1 ||
	    EVP_DigestUpdate(ctx, seed, seed_len) != 1 ||
	    EVP_DigestFinal_ex(ctx, digest, NULL) != 1) {
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	EVP_MD_CTX_free(ctx);

	char *key = malloc(33);
	if (!key) return -1;
	for (int i = 0; i < 16; i++)
		snprintf(key + i * 2, 3, "%02x", digest[i]);
	key[32] = '\0';
	*out_key = key;
	return 0;
}

/* ============================================================
 * Local IP Discovery
 * ============================================================ */

int list_local_ips(char ips[][64], int max_ips)
{
	struct ifaddrs *ifaddr, *ifa;
	int count = 0;

	if (getifaddrs(&ifaddr) == -1)
		return 0;

	for (ifa = ifaddr; ifa && count < max_ips; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;
		/* Skip loopback */
		struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
		const char *ip = inet_ntoa(sa->sin_addr);
		if (strcmp(ip, "127.0.0.1") == 0)
			continue;
		strncpy(ips[count], ip, 63);
		ips[count][63] = '\0';
		count++;
	}
	freeifaddrs(ifaddr);
	return count;
}

/* ============================================================
 * STUN Discovery
 * ============================================================ */

/* Build a STUN Binding Request
 * Format: [type:2][length:2][magic_cookie:4][txid:12]
 * Total header = 20 bytes
 */
static int stun_build_request(uint8_t *buf, size_t buf_len, uint8_t *txid_out)
{
	if (buf_len < 20) return -1;

	/* Type = Binding Request (0x0001) */
	buf[0] = 0x00;
	buf[1] = 0x01;
	/* Length = 0 (no attributes) */
	buf[2] = 0x00;
	buf[3] = 0x00;
	/* Magic Cookie */
	buf[4] = 0x21;
	buf[5] = 0x12;
	buf[6] = 0xA4;
	buf[7] = 0x42;
	/* Transaction ID (12 random bytes) */
	RAND_bytes(txid_out, STUN_TXID_LEN);
	memcpy(buf + 8, txid_out, STUN_TXID_LEN);

	return 20;
}

/* Parse a STUN Binding Response and extract address from an attribute.
 * attr_type: STUN_ATTR_XOR_MAPPED_ADDR, STUN_ATTR_MAPPED_ADDR, etc.
 * Returns 0 on success, fills out_ip and out_port.
 */
static int stun_parse_response(const uint8_t *buf, size_t len,
			       const uint8_t *expected_txid,
			       uint16_t attr_type,
			       char *out_ip, size_t ip_len, int *out_port)
{
	if (len < 20) return -1;

	/* Check type */
	uint16_t msg_type = (buf[0] << 8) | buf[1];
	if (msg_type != STUN_BINDING_RESPONSE) return -1;

	/* Check magic cookie */
	if (buf[4] != 0x21 || buf[5] != 0x12 || buf[6] != 0xA4 || buf[7] != 0x42)
		return -1;

	/* Check transaction ID */
	if (memcmp(buf + 8, expected_txid, STUN_TXID_LEN) != 0)
		return -1;

	/* Parse attributes */
	uint16_t msg_len = (buf[2] << 8) | buf[3];
	size_t pos = 20;
	size_t end = 20 + msg_len;
	if (end > len) end = len;

	while (pos + 4 <= end) {
		uint16_t a_type = (buf[pos] << 8) | buf[pos + 1];
		uint16_t a_len = (buf[pos + 2] << 8) | buf[pos + 3];
		pos += 4;
		if (pos + a_len > end) break;

		if (a_type == attr_type) {
			/* Parse address attribute */
			if (a_len < 8) return -1;
			uint8_t family = buf[pos + 1];
			uint16_t port;
			uint32_t ip;

			if (family == 0x01) { /* IPv4 */
				port = (buf[pos + 2] << 8) | buf[pos + 3];
				memcpy(&ip, buf + pos + 4, 4);

				if (attr_type == STUN_ATTR_XOR_MAPPED_ADDR) {
					/* XOR with magic cookie */
					port ^= (STUN_MAGIC_COOKIE >> 16);
					ip ^= htonl(STUN_MAGIC_COOKIE);
				}

				struct in_addr addr;
				memcpy(&addr, &ip, 4);
				const char *ip_str = inet_ntoa(addr);
				if (ip_str) {
					strncpy(out_ip, ip_str, ip_len - 1);
					out_ip[ip_len - 1] = '\0';
					*out_port = port;
					return 0;
				}
			}
		}

		/* Attributes are padded to 4-byte boundary */
		pos += a_len;
		if (a_len % 4 != 0)
			pos += 4 - (a_len % 4);
	}
	return -1;
}

/* Extract IP:port from a STUN address attribute */
static int stun_extract_addr(const uint8_t *buf, size_t len,
			     const uint8_t *expected_txid,
			     uint16_t attr_type,
			     char *out, size_t out_len)
{
	char ip[64];
	int port;
	if (stun_parse_response(buf, len, expected_txid, attr_type, ip, sizeof(ip), &port) != 0)
		return -1;
	snprintf(out, out_len, "%s:%d", ip, port);
	return 0;
}

/* Send STUN request and wait for response */
static int stun_do_request(int sock, const struct sockaddr_in *server_addr,
			   uint8_t *out_txid,
			   uint8_t *resp_buf, size_t resp_buf_len, size_t *resp_len)
{
	uint8_t req[20];
	int req_len = stun_build_request(req, sizeof(req), out_txid);
	if (req_len < 0) return -1;

	/* Send request */
	ssize_t sent = sendto(sock, req, req_len, 0,
			      (const struct sockaddr *)server_addr,
			      sizeof(*server_addr));
	if (sent != req_len) return -1;

	/* Wait for response with timeout */
	struct timeval tv = { .tv_sec = STUN_TIMEOUT_MS / 1000,
			     .tv_usec = (STUN_TIMEOUT_MS % 1000) * 1000 };
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);
	ssize_t n = recvfrom(sock, resp_buf, resp_buf_len, 0,
			     (struct sockaddr *)&from, &from_len);
	if (n < 20) return -1;
	*resp_len = (size_t)n;
	return 0;
}

/* Resolve a hostname:port to sockaddr_in.
 * If port_str is NULL, uses default STUN port 3478.
 * Supports "host" or "host:port" format.
 */
static int resolve_stun_server(const char *server, int default_port,
			       struct sockaddr_in *out)
{
	char host[256];
	int port = default_port;

	strncpy(host, server, sizeof(host) - 1);
	host[sizeof(host) - 1] = '\0';

	/* Check for :port suffix */
	char *colon = strrchr(host, ':');
	if (colon && colon != host) {
		*colon = '\0';
		port = atoi(colon + 1);
		if (port <= 0) port = default_port;
	}

	memset(out, 0, sizeof(*out));
	out->sin_family = AF_INET;
	out->sin_port = htons(port);

	if (inet_pton(AF_INET, host, &out->sin_addr) == 1)
		return 0;

	/* DNS resolve */
	struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
	struct addrinfo *res = NULL;
	char port_str[8];
	snprintf(port_str, sizeof(port_str), "%d", port);

	if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
		return -1;

	memcpy(out, res->ai_addr, sizeof(*out));
	freeaddrinfo(res);
	return 0;
}

int stun_discover(const char **stun_servers, const char *local_addr,
		  struct stun_result *result)
{
	if (!stun_servers || !result) return -1;
	memset(result, 0, sizeof(*result));

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		debug(LOG_ERR, "STUN: socket() failed: %s", strerror(errno));
		return -1;
	}

	/* Bind to local address if specified */
	if (local_addr) {
		struct sockaddr_in laddr;
		memset(&laddr, 0, sizeof(laddr));
		laddr.sin_family = AF_INET;
		if (inet_pton(AF_INET, local_addr, &laddr.sin_addr) != 1) {
			close(sock);
			return -1;
		}
		bind(sock, (struct sockaddr *)&laddr, sizeof(laddr));
	}

	/* Store local address */
	socklen_t slen = sizeof(result->local_addr);
	getsockname(sock, (struct sockaddr *)&result->local_addr, &slen);

	for (int s = 0; stun_servers[s] && result->addr_count < MAX_MAPPED_ADDRS; s++) {
		struct sockaddr_in server_addr;
		if (resolve_stun_server(stun_servers[s], STUN_PORT, &server_addr) != 0) {
			debug(LOG_WARNING, "STUN: cannot resolve server '%s'", stun_servers[s]);
			continue;
		}

		debug(LOG_DEBUG, "STUN: querying %s:%d",
		      inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));

		uint8_t txid[STUN_TXID_LEN];
		uint8_t resp[1024];
		size_t resp_len = 0;

		if (stun_do_request(sock, &server_addr, txid, resp, sizeof(resp), &resp_len) != 0) {
			debug(LOG_WARNING, "STUN: no response from %s", stun_servers[s]);
			continue;
		}

		/* Try XOR-Mapped-Address first, then Mapped-Address */
		char mapped[64];
		if (stun_extract_addr(resp, resp_len, txid,
				      STUN_ATTR_XOR_MAPPED_ADDR, mapped, sizeof(mapped)) == 0 ||
		    stun_extract_addr(resp, resp_len, txid,
				      STUN_ATTR_MAPPED_ADDR, mapped, sizeof(mapped)) == 0) {
			strncpy(result->addrs[result->addr_count].addr, mapped, 63);
			result->addr_count++;
			debug(LOG_DEBUG, "STUN: mapped addr = %s", mapped);
		}

		/* Try to get ChangedAddress / OtherAddress for second mapping */
		char other[64];
		if (stun_extract_addr(resp, resp_len, txid,
				      STUN_ATTR_OTHER_ADDR, other, sizeof(other)) == 0) {
			debug(LOG_DEBUG, "STUN: other addr = %s (sending second request)", other);

			struct sockaddr_in other_addr;
			if (resolve_stun_server(other, STUN_PORT, &other_addr) == 0 &&
			    result->addr_count < MAX_MAPPED_ADDRS) {
				uint8_t txid2[STUN_TXID_LEN];
				uint8_t resp2[1024];
				size_t resp2_len = 0;

				if (stun_do_request(sock, &other_addr, txid2,
						    resp2, sizeof(resp2), &resp2_len) == 0) {
					char mapped2[64];
					if (stun_extract_addr(resp2, resp2_len, txid2,
							      STUN_ATTR_XOR_MAPPED_ADDR,
							      mapped2, sizeof(mapped2)) == 0 ||
					    stun_extract_addr(resp2, resp2_len, txid2,
							      STUN_ATTR_MAPPED_ADDR,
							      mapped2, sizeof(mapped2)) == 0) {
						strncpy(result->addrs[result->addr_count].addr,
							mapped2, 63);
						result->addr_count++;
						debug(LOG_DEBUG, "STUN: second mapped addr = %s", mapped2);
					}
				}
			}
		}
	}

	close(sock);

	if (result->addr_count == 0) {
		debug(LOG_ERR, "STUN: no addresses discovered");
		return -1;
	}
	return 0;
}

/* ============================================================
 * NAT Feature Classification
 * ============================================================ */

int classify_nat_feature(const char **addrs, int addr_count,
			 const char **local_ips, int local_count,
			 struct nat_feature *feature)
{
	if (!addrs || addr_count <= 1 || !feature)
		return -1;

	memset(feature, 0, sizeof(*feature));
	bool ip_changed = false;
	bool port_changed = false;
	char base_ip[64] = {0};
	char base_port[16] = {0};
	int port_max = 0, port_min = 0;

	for (int i = 0; i < addr_count; i++) {
		char ip[64], port_str[16];
		char *colon = strrchr(addrs[i], ':');
		if (!colon) return -1;

		size_t ip_len = colon - addrs[i];
		if (ip_len >= sizeof(ip)) ip_len = sizeof(ip) - 1;
		memcpy(ip, addrs[i], ip_len);
		ip[ip_len] = '\0';
		strncpy(port_str, colon + 1, sizeof(port_str) - 1);

		int port_num = atoi(port_str);
		if (port_num <= 0) return -1;

		/* Check if external IP matches a local IP (public network) */
		for (int j = 0; j < local_count; j++) {
			if (strcmp(ip, local_ips[j]) == 0) {
				feature->public_network = true;
				break;
			}
		}

		if (i == 0) {
			strncpy(base_ip, ip, sizeof(base_ip) - 1);
			strncpy(base_port, port_str, sizeof(base_port) - 1);
			port_max = port_num;
			port_min = port_num;
			continue;
		}

		if (port_num > port_max) port_max = port_num;
		if (port_num < port_min) port_min = port_num;

		if (strcmp(base_ip, ip) != 0)
			ip_changed = true;
		if (strcmp(base_port, port_str) != 0)
			port_changed = true;
	}

	if (ip_changed && port_changed) {
		strcpy(feature->nat_type, NAT_TYPE_HARD);
		strcpy(feature->behavior, NAT_BEHAVIOR_BOTH_CHANGED);
	} else if (ip_changed) {
		strcpy(feature->nat_type, NAT_TYPE_HARD);
		strcpy(feature->behavior, NAT_BEHAVIOR_IP_CHANGED);
	} else if (port_changed) {
		strcpy(feature->nat_type, NAT_TYPE_HARD);
		strcpy(feature->behavior, NAT_BEHAVIOR_PORT_CHANGED);
		feature->ports_difference = port_max - port_min;
		if (feature->ports_difference >= 1 && feature->ports_difference <= 5)
			feature->regular_ports_change = true;
	} else {
		strcpy(feature->nat_type, NAT_TYPE_EASY);
		strcpy(feature->behavior, NAT_BEHAVIOR_NO_CHANGE);
	}

	debug(LOG_DEBUG, "NAT classification: type=%s, behavior=%s, ports_diff=%d, regular=%d, public=%d",
	      feature->nat_type, feature->behavior, feature->ports_difference,
	      feature->regular_ports_change, feature->public_network);

	return 0;
}

/* ============================================================
 * UDP Hole-Punch Packet Encoding/Decoding
 *
 * Wire format (compatible with frp):
 *   1. Serialize NatHoleSid as: [type_byte '5'][JSON content]
 *   2. Encrypt with AES-128-CFB:
 *      - Key: PBKDF2(secret_key, salt="crypto", iter=64, keylen=16, SHA1)
 *      - IV: random 16 bytes, prepended to ciphertext
 *      - Output: [IV:16][encrypted data]
 *
 * Note: frp uses golib/crypto which prepends the 2-byte type + 8-byte length
 * before encryption. We must match this format.
 * ============================================================ */

/* Derive AES key from secret key using PBKDF2 */
static void derive_nathole_key(const char *secret_key, uint8_t *out_key)
{
	const char *salt = "crypto";
	fastpbkdf2_hmac_sha1(
		(const uint8_t *)secret_key, strlen(secret_key),
		(const uint8_t *)salt, strlen(salt),
		64,        /* iterations */
		out_key,   /* output */
		16         /* key length */
	);
}

/* Encrypt data using AES-128-CFB.
 * Output: [IV:16][ciphertext]
 * Returns total output length, or -1 on error.
 */
static int aes_cfb_encrypt(const uint8_t *in, size_t in_len,
			   const uint8_t *key,
			   uint8_t *out, size_t out_len)
{
	if (out_len < in_len + 16) return -1;

	/* Generate random IV */
	uint8_t iv[16];
	RAND_bytes(iv, 16);
	memcpy(out, iv, 16);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	int ret = -1;
	int outl = 0, total = 0;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, key, iv) != 1)
		goto done;
	/* CFB mode doesn't need padding, but we must finalize to flush */
	if (EVP_EncryptUpdate(ctx, out + 16, &outl, in, in_len) != 1)
		goto done;
	total = outl;
	if (EVP_EncryptFinal_ex(ctx, out + 16 + total, &outl) != 1)
		goto done;
	total += outl;
	ret = 16 + total;

done:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

/* Decrypt data using AES-128-CFB.
 * Input: [IV:16][ciphertext]
 * Output: plaintext (in-place or separate buffer)
 * Returns plaintext length, or -1 on error.
 */
static int aes_cfb_decrypt(const uint8_t *in, size_t in_len,
			   const uint8_t *key,
			   uint8_t *out, size_t out_len)
{
	if (in_len < 16) return -1;

	const uint8_t *iv = in;
	const uint8_t *ciphertext = in + 16;
	size_t ciphertext_len = in_len - 16;

	if (out_len < ciphertext_len) return -1;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	int ret = -1;
	int outl = 0, total = 0;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, key, iv) != 1)
		goto done;
	if (EVP_DecryptUpdate(ctx, out, &outl, ciphertext, ciphertext_len) != 1)
		goto done;
	total = outl;
	if (EVP_DecryptFinal_ex(ctx, out + total, &outl) != 1)
		goto done;
	total += outl;
	ret = total;

done:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

/* frp golib/crypto format:
 * Before encryption: [type:2 bytes big-endian][length:8 bytes big-endian int64][json]
 * The "type" is the msg type byte repeated? No - looking at frp source:
 * msg.WriteMsg writes: [type_byte:1][content_length:8 BE int64][json_bytes]
 * Then crypto.Encode encrypts that whole thing.
 *
 * Wait, let me re-read the frp source for msg.WriteMsg:
 * From golib/msg/json/pack.go:
 *   WriteMsg(w, m) → writes type byte + 8-byte length + json
 *
 * So the plaintext to encrypt is:
 *   [type_byte = '5'][length:8 bytes BE int64][json_content]
 *
 * And the encrypted output is:
 *   [IV:16][encrypted of above]
 */

/* Build the plaintext payload for NatHoleSid in frp wire format */
static int build_sid_plaintext(const struct nathole_sid_msg *msg,
			       uint8_t *out, size_t out_len)
{
	/* Build JSON */
	struct json_object *jobj = json_object_new_object();
	if (!jobj) return -1;

	if (msg->transaction_id)
		json_object_object_add(jobj, "transaction_id",
			json_object_new_string(msg->transaction_id));
	if (msg->sid)
		json_object_object_add(jobj, "sid",
			json_object_new_string(msg->sid));
	json_object_object_add(jobj, "response",
		json_object_new_boolean(msg->response));
	if (msg->nonce)
		json_object_object_add(jobj, "nonce",
			json_object_new_string(msg->nonce));

	const char *json_str = json_object_to_json_string(jobj);
	size_t json_len = strlen(json_str);

	/* frp wire format: [type:1][length:8 BE int64][json] */
	size_t total = 1 + 8 + json_len;
	if (total > out_len) {
		json_object_put(jobj);
		return -1;
	}

	out[0] = TypeNatHoleSid; /* '5' */
	uint64_t be_len = hton64((uint64_t)json_len);
	memcpy(out + 1, &be_len, 8);
	memcpy(out + 9, json_str, json_len);

	json_object_put(jobj);
	return (int)total;
}

int nathole_encode_sid(const struct nathole_sid_msg *msg,
		       const char *secret_key,
		       uint8_t **out_buf, size_t *out_len)
{
	if (!msg || !secret_key || !out_buf || !out_len) return -1;

	/* Build plaintext */
	uint8_t plain[2048];
	int plain_len = build_sid_plaintext(msg, plain, sizeof(plain));
	if (plain_len < 0) return -1;

	/* Derive key */
	uint8_t key[16];
	derive_nathole_key(secret_key, key);

	/* Encrypt */
	size_t enc_max = plain_len + 32; /* IV + padding */
	uint8_t *enc = malloc(enc_max);
	if (!enc) return -1;

	int enc_len = aes_cfb_encrypt(plain, plain_len, key, enc, enc_max);
	if (enc_len < 0) {
		free(enc);
		return -1;
	}

	*out_buf = enc;
	*out_len = (size_t)enc_len;
	return 0;
}

int nathole_decode_sid(const uint8_t *data, size_t data_len,
		       const char *secret_key,
		       struct nathole_sid_msg *msg)
{
	if (!data || data_len < 17 || !secret_key || !msg) return -1;

	/* Derive key */
	uint8_t key[16];
	derive_nathole_key(secret_key, key);

	/* Decrypt */
	uint8_t plain[2048];
	int plain_len = aes_cfb_decrypt(data, data_len, key, plain, sizeof(plain));
	if (plain_len < 10) return -1; /* minimum: type(1) + length(8) + "{}"(2) */

	/* Parse frp wire format: [type:1][length:8 BE int64][json] */
	if (plain[0] != TypeNatHoleSid)
		return -1;

	uint64_t json_len;
	memcpy(&json_len, plain + 1, 8);
	json_len = ntoh64(json_len);

	if (json_len > (uint64_t)(plain_len - 9))
		return -1;

	/* Parse JSON */
	char *json_str = malloc(json_len + 1);
	if (!json_str) return -1;
	memcpy(json_str, plain + 9, json_len);
	json_str[json_len] = '\0';

	struct json_object *jobj = json_tokener_parse(json_str);
	free(json_str);
	if (!jobj) return -1;

	memset(msg, 0, sizeof(*msg));

	struct json_object *val;
	if (json_object_object_get_ex(jobj, "transaction_id", &val))
		msg->transaction_id = strdup(json_object_get_string(val));
	if (json_object_object_get_ex(jobj, "sid", &val))
		msg->sid = strdup(json_object_get_string(val));
	if (json_object_object_get_ex(jobj, "response", &val))
		msg->response = json_object_get_boolean(val);
	if (json_object_object_get_ex(jobj, "nonce", &val))
		msg->nonce = strdup(json_object_get_string(val));

	json_object_put(jobj);
	return 0;
}

void nathole_sid_msg_free(struct nathole_sid_msg *msg)
{
	if (!msg) return;
	SAFE_FREE(msg->transaction_id);
	SAFE_FREE(msg->sid);
	SAFE_FREE(msg->nonce);
}

void nathole_resp_free(struct nathole_resp *resp)
{
	if (!resp) return;
	SAFE_FREE(resp->transaction_id);
	SAFE_FREE(resp->sid);
	SAFE_FREE(resp->protocol);
	SAFE_FREE(resp->error);
	for (int i = 0; i < resp->candidate_addrs_count; i++)
		SAFE_FREE(resp->candidate_addrs[i]);
	for (int i = 0; i < resp->assisted_addrs_count; i++)
		SAFE_FREE(resp->assisted_addrs[i]);
	resp->candidate_addrs_count = 0;
	resp->assisted_addrs_count = 0;
}
