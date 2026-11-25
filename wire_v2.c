// SPDX-License-Identifier: GPL-3.0-only

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <json-c/json.h>
#include "ssl_compat.h"

#include "wire_v2.h"
#include "config.h"
#include "debug.h"
#include "common.h"

int wire_protocol_is_v2(void)
{
	struct common_conf *c = get_common_config();
	return c && c->wire_protocol && strcmp(c->wire_protocol, "v2") == 0;
}

void wire_v2_reset(void)
{
}

uint16_t wire_v2_msg_type_to_id(enum msg_type t)
{
	switch (t) {
	case TypeLogin: return 1;
	case TypeLoginResp: return 2;
	case TypeNewProxy: return 3;
	case TypeNewProxyResp: return 4;
	case TypeCloseProxy: return 5;
	case TypeNewWorkConn: return 6;
	case TypeReqWorkConn: return 7;
	case TypeStartWorkConn: return 8;
	case TypeNewVisitorConn: return 9;
	case TypeNewVisitorConnResp: return 10;
	case TypePing: return 11;
	case TypePong: return 12;
	case TypeUDPPacket: return 13;
	case TypeNatHoleVisitor: return 14;
	case TypeNatHoleClient: return 15;
	case TypeNatHoleResp: return 16;
	case TypeNatHoleSid: return 17;
	case TypeNatHoleReport: return 18;
	default: return 0;
	}
}

enum msg_type wire_v2_id_to_msg_type(uint16_t id)
{
	switch (id) {
	case 1: return TypeLogin;
	case 2: return TypeLoginResp;
	case 3: return TypeNewProxy;
	case 4: return TypeNewProxyResp;
	case 5: return TypeCloseProxy;
	case 6: return TypeNewWorkConn;
	case 7: return TypeReqWorkConn;
	case 8: return TypeStartWorkConn;
	case 9: return TypeNewVisitorConn;
	case 10: return TypeNewVisitorConnResp;
	case 11: return TypePing;
	case 12: return TypePong;
	case 13: return TypeUDPPacket;
	case 14: return TypeNatHoleVisitor;
	case 15: return TypeNatHoleClient;
	case 16: return TypeNatHoleResp;
	case 17: return TypeNatHoleSid;
	case 18: return TypeNatHoleReport;
	default: return 0;
	}
}

int wire_v2_encode_frame(uint16_t type, const uint8_t *payload, uint32_t plen,
			 uint8_t **out, size_t *out_len)
{
	size_t total = 8 + plen;
	uint8_t *buf = malloc(total);
	if (!buf)
		return -1;
	buf[0] = (uint8_t)(type >> 8);
	buf[1] = (uint8_t)type;
	buf[2] = 0;
	buf[3] = 0;
	buf[4] = (uint8_t)(plen >> 24);
	buf[5] = (uint8_t)(plen >> 16);
	buf[6] = (uint8_t)(plen >> 8);
	buf[7] = (uint8_t)plen;
	if (plen && payload)
		memcpy(buf + 8, payload, plen);
	*out = buf;
	*out_len = total;
	return 0;
}

int wire_v2_parse_frame(const uint8_t *buf, size_t len, uint16_t *type,
			const uint8_t **payload, uint32_t *plen)
{
	if (len < 8)
		return 0;
	uint16_t flags = ((uint16_t)buf[2] << 8) | buf[3];
	if (flags != 0) {
		debug(LOG_ERR, "v2 unsupported frame flags %u", flags);
		return -1;
	}
	uint32_t l = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
		     ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
	if (l > 64 * 1024) {
		debug(LOG_ERR, "v2 frame payload %u too large", l);
		return -1;
	}
	if (len < 8 + l)
		return 0;
	*type = ((uint16_t)buf[0] << 8) | buf[1];
	*payload = buf + 8;
	*plen = l;
	return (int)(8 + l);
}

int wire_v2_build_client_hello_json(const char *transport, int tls, int tcp_mux,
				    uint8_t **json, size_t *jlen)
{
	uint8_t rnd[32];
	if (RAND_bytes(rnd, sizeof(rnd)) != 1)
		return -1;

	char b64[64];
	int n = EVP_EncodeBlock((unsigned char *)b64, rnd, (int)sizeof(rnd));
	if (n < 0)
		return -1;
	b64[n] = '\0';

	json_object *root = json_object_new_object();
	json_object *bootstrap = json_object_new_object();
	json_object_object_add(bootstrap, "transport",
			       json_object_new_string(transport ? transport : "tcp"));
	if (tls)
		json_object_object_add(bootstrap, "tls", json_object_new_boolean(1));
	if (tcp_mux)
		json_object_object_add(bootstrap, "tcpMux", json_object_new_boolean(1));
	json_object_object_add(root, "bootstrap", bootstrap);

	json_object *caps = json_object_new_object();
	json_object *msg = json_object_new_object();
	json_object *codecs = json_object_new_array();
	json_object_array_add(codecs, json_object_new_string("json"));
	json_object_object_add(msg, "codecs", codecs);
	json_object_object_add(caps, "message", msg);

	json_object *crypto = json_object_new_object();
	json_object *algs = json_object_new_array();
	json_object_array_add(algs, json_object_new_string(WIRE_V2_ALG_AES256GCM));
	json_object_object_add(crypto, "algorithms", algs);
	json_object_object_add(crypto, "clientRandom", json_object_new_string(b64));
	json_object_object_add(caps, "crypto", crypto);
	json_object_object_add(root, "capabilities", caps);

	const char *s = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
	if (!s) {
		json_object_put(root);
		return -1;
	}
	*jlen = strlen(s);
	*json = malloc(*jlen);
	if (!*json) {
		json_object_put(root);
		return -1;
	}
	memcpy(*json, s, *jlen);
	json_object_put(root);
	return 0;
}

int wire_v2_parse_server_hello_json(const uint8_t *json, size_t jlen,
				    char *alg, size_t alg_sz,
				    char *errbuf, size_t err_sz)
{
	char *tmp = malloc(jlen + 1);
	if (!tmp)
		return -1;
	memcpy(tmp, json, jlen);
	tmp[jlen] = '\0';
	json_object *root = json_tokener_parse(tmp);
	free(tmp);
	if (!root)
		return -1;

	json_object *jerr = NULL;
	if (json_object_object_get_ex(root, "error", &jerr) &&
	    json_object_get_string(jerr) && json_object_get_string(jerr)[0]) {
		if (errbuf && err_sz)
			snprintf(errbuf, err_sz, "%s", json_object_get_string(jerr));
		json_object_put(root);
		return -1;
	}

	json_object *sel = NULL, *crypto = NULL, *jalg = NULL;
	if (!json_object_object_get_ex(root, "selected", &sel) ||
	    !json_object_object_get_ex(sel, "crypto", &crypto) ||
	    !json_object_object_get_ex(crypto, "algorithm", &jalg)) {
		json_object_put(root);
		return -1;
	}
	const char *a = json_object_get_string(jalg);
	if (!a || strcmp(a, WIRE_V2_ALG_AES256GCM) != 0) {
		debug(LOG_ERR, "v2 unsupported AEAD algorithm: %s", a ? a : "(null)");
		json_object_put(root);
		return -1;
	}
	if (alg && alg_sz)
		snprintf(alg, alg_sz, "%s", a);
	json_object_put(root);
	return 0;
}

static void transcript_part(EVP_MD_CTX *ctx, const char *label,
			    const uint8_t *payload, size_t plen)
{
	uint8_t z = 0;
	uint8_t lenbe[8];
	EVP_DigestUpdate(ctx, &z, 1);
	EVP_DigestUpdate(ctx, label, strlen(label));
	EVP_DigestUpdate(ctx, &z, 1);
	uint64_t plen64 = (uint64_t)plen;
	lenbe[0] = (uint8_t)(plen64 >> 56);
	lenbe[1] = (uint8_t)(plen64 >> 48);
	lenbe[2] = (uint8_t)(plen64 >> 40);
	lenbe[3] = (uint8_t)(plen64 >> 32);
	lenbe[4] = (uint8_t)(plen64 >> 24);
	lenbe[5] = (uint8_t)(plen64 >> 16);
	lenbe[6] = (uint8_t)(plen64 >> 8);
	lenbe[7] = (uint8_t)plen64;
	EVP_DigestUpdate(ctx, lenbe, 8);
	if (plen)
		EVP_DigestUpdate(ctx, payload, plen);
}

void wire_v2_hash_transcript(const uint8_t *ch, size_t chlen,
			     const uint8_t *sh, size_t shlen,
			     uint8_t out[32])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	static const char label[] = "frp wire v2 crypto transcript";
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, label, strlen(label));
	transcript_part(ctx, "client hello", ch, chlen);
	transcript_part(ctx, "server hello", sh, shlen);
	unsigned int n = 32;
	EVP_DigestFinal_ex(ctx, out, &n);
	EVP_MD_CTX_free(ctx);
}

int wire_v2_encode_message(enum msg_type t, const char *json, size_t jlen,
			   uint8_t **out, size_t *out_len)
{
	uint16_t id = wire_v2_msg_type_to_id(t);
	if (!id || jlen > (size_t)UINT32_MAX - 2)
		return -1;
	uint32_t plen = (uint32_t)(2 + jlen);
	uint8_t *payload = malloc(plen);
	if (!payload)
		return -1;
	payload[0] = (uint8_t)(id >> 8);
	payload[1] = (uint8_t)id;
	if (jlen)
		memcpy(payload + 2, json, jlen);
	int rc = wire_v2_encode_frame(WIRE_V2_FRAME_MESSAGE, payload, plen, out, out_len);
	free(payload);
	return rc;
}

int wire_v2_payload_to_v1(const uint8_t *payload, uint32_t plen,
			  uint8_t **v1, size_t *v1_len)
{
	if (!payload || plen < 2)
		return -1;
	uint16_t id = ((uint16_t)payload[0] << 8) | payload[1];
	enum msg_type t = wire_v2_id_to_msg_type(id);
	if (!t)
		return -1;
	uint32_t jlen = plen - 2;
	size_t total = sizeof(struct msg_hdr) + jlen;
	uint8_t *buf = calloc(1, total);
	if (!buf)
		return -1;
	struct msg_hdr *h = (struct msg_hdr *)buf;
	h->type = (char)t;
	h->length = msg_hton((uint64_t)jlen);
	if (jlen)
		memcpy(h->data, payload + 2, jlen);
	*v1 = buf;
	*v1_len = total;
	return 0;
}
