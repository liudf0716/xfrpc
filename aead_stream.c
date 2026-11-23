// SPDX-License-Identifier: GPL-3.0-only

#include <string.h>
#include <stdlib.h>

#include "ssl_compat.h"
#include <openssl/hmac.h>
#include "aead_stream.h"
#include "debug.h"

static int increment_nonce(uint8_t *nonce, size_t n)
{
	for (int i = (int)n - 1; i >= 0; i--) {
		nonce[i]++;
		if (nonce[i] != 0)
			return 1;
	}
	return 0;
}

static int hmac_sha256(const uint8_t *key, size_t klen,
		       const uint8_t *data, size_t dlen, uint8_t out[32])
{
	unsigned int len = 32;
	if (!HMAC(EVP_sha256(), key, (int)klen, data, dlen, out, &len))
		return -1;
	return 0;
}

int hkdf_sha256_32(const uint8_t *ikm, size_t ikm_len,
		   const uint8_t *salt, size_t salt_len,
		   const uint8_t *info, size_t info_len,
		   uint8_t out[AEAD_KEY_SIZE])
{
	uint8_t prk[32];
	uint8_t zeros[32];

	if (!salt || salt_len == 0) {
		memset(zeros, 0, sizeof(zeros));
		salt = zeros;
		salt_len = 32;
	}
	if (hmac_sha256(salt, salt_len, ikm, ikm_len, prk) != 0)
		return -1;

	uint8_t *tmp = malloc(info_len + 1);
	if (!tmp)
		return -1;
	memcpy(tmp, info, info_len);
	tmp[info_len] = 0x01;
	int ret = hmac_sha256(prk, 32, tmp, info_len + 1, out);
	free(tmp);
	return ret;
}

int derive_v2_control_keys(const uint8_t *token, size_t token_len,
			   const uint8_t transcript[32],
			   const char *algorithm,
			   uint8_t c2s[AEAD_KEY_SIZE],
			   uint8_t s2c[AEAD_KEY_SIZE])
{
	char info_c2s[128];
	char info_s2c[128];
	int n1 = snprintf(info_c2s, sizeof(info_c2s),
			  "frp wire v2 control aead %s client-to-server", algorithm);
	int n2 = snprintf(info_s2c, sizeof(info_s2c),
			  "frp wire v2 control aead %s server-to-client", algorithm);
	if (n1 < 0 || n2 < 0)
		return -1;
	if (hkdf_sha256_32(token, token_len, transcript, 32,
			   (uint8_t *)info_c2s, (size_t)n1, c2s) != 0)
		return -1;
	if (hkdf_sha256_32(token, token_len, transcript, 32,
			   (uint8_t *)info_s2c, (size_t)n2, s2c) != 0)
		return -1;
	return 0;
}

static int gcm_seal(const uint8_t key[AEAD_KEY_SIZE], const uint8_t nonce[12],
		    const uint8_t *aad, size_t aad_len,
		    const uint8_t *pt, size_t pt_len,
		    uint8_t *out, size_t *out_len)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len = 0, ct_len = 0;
	if (!ctx)
		return -1;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto err;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
		goto err;
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
		goto err;
	if (aad && aad_len) {
		if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
			goto err;
	}
	if (pt_len) {
		if (EVP_EncryptUpdate(ctx, out, &len, pt, (int)pt_len) != 1)
			goto err;
		ct_len = len;
	}
	if (EVP_EncryptFinal_ex(ctx, out + ct_len, &len) != 1)
		goto err;
	ct_len += len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + ct_len) != 1)
		goto err;
	ct_len += 16;
	*out_len = (size_t)ct_len;
	EVP_CIPHER_CTX_free(ctx);
	return 0;
err:
	EVP_CIPHER_CTX_free(ctx);
	return -1;
}

static int gcm_open(const uint8_t key[AEAD_KEY_SIZE], const uint8_t nonce[12],
		    const uint8_t *aad, size_t aad_len,
		    const uint8_t *ct, size_t ct_len,
		    uint8_t *out, size_t *out_len)
{
	if (ct_len < 16)
		return -1;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len = 0, pt_len = 0;
	if (!ctx)
		return -1;
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto err;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
		goto err;
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
		goto err;
	if (aad && aad_len) {
		if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
			goto err;
	}
	if (EVP_DecryptUpdate(ctx, out, &len, ct, (int)(ct_len - 16)) != 1)
		goto err;
	pt_len = len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
				(void *)(ct + ct_len - 16)) != 1)
		goto err;
	if (EVP_DecryptFinal_ex(ctx, out + pt_len, &len) != 1)
		goto err;
	pt_len += len;
	*out_len = (size_t)pt_len;
	EVP_CIPHER_CTX_free(ctx);
	return 0;
err:
	EVP_CIPHER_CTX_free(ctx);
	return -1;
}

int aead_writer_init(struct aead_writer *w, const uint8_t key[AEAD_KEY_SIZE])
{
	if (!w || !key)
		return -1;
	memset(w, 0, sizeof(*w));
	memcpy(w->key, key, AEAD_KEY_SIZE);
	if (RAND_bytes(w->nonce, AEAD_GCM_NONCE_SIZE) != 1)
		return -1;
	memcpy(w->stream_nonce, w->nonce, AEAD_GCM_NONCE_SIZE);
	return 0;
}

void aead_writer_free(struct aead_writer *w)
{
	if (w)
		memset(w, 0, sizeof(*w));
}

int aead_writer_seal(struct aead_writer *w, const uint8_t *pt, size_t pt_len,
		     uint8_t **out, size_t *out_len)
{
	if (!w || !pt || !out || !out_len || pt_len == 0)
		return -1;

	size_t num_chunks = (pt_len + AEAD_MAX_PAYLOAD - 1) / AEAD_MAX_PAYLOAD;
	size_t prefix = w->header_sent ? 0 : AEAD_GCM_NONCE_SIZE;
	size_t total = prefix + num_chunks * (4 + AEAD_GCM_TAG_SIZE) + pt_len;

	uint8_t *buf = malloc(total);
	if (!buf)
		return -1;

	size_t out_off = 0;
	if (!w->header_sent) {
		memcpy(buf, w->nonce, AEAD_GCM_NONCE_SIZE);
		out_off = AEAD_GCM_NONCE_SIZE;
		w->header_sent = 1;
	}

	size_t remaining = pt_len;
	const uint8_t *cur_pt = pt;

	while (remaining > 0) {
		size_t chunk_len = remaining > AEAD_MAX_PAYLOAD ? AEAD_MAX_PAYLOAD : remaining;
		uint8_t header[4];
		uint32_t ct_len_field = (uint32_t)(chunk_len + AEAD_GCM_TAG_SIZE);
		header[0] = (uint8_t)(ct_len_field >> 24);
		header[1] = (uint8_t)(ct_len_field >> 16);
		header[2] = (uint8_t)(ct_len_field >> 8);
		header[3] = (uint8_t)ct_len_field;

		uint8_t aad[AEAD_GCM_NONCE_SIZE + 4];
		memcpy(aad, w->stream_nonce, AEAD_GCM_NONCE_SIZE);
		memcpy(aad + AEAD_GCM_NONCE_SIZE, header, 4);

		memcpy(buf + out_off, header, 4);
		out_off += 4;

		size_t clen = 0;
		if (gcm_seal(w->key, w->nonce, aad, sizeof(aad), cur_pt, chunk_len,
			     buf + out_off, &clen) != 0) {
			free(buf);
			return -1;
		}
		out_off += clen;

		if (!increment_nonce(w->nonce, AEAD_GCM_NONCE_SIZE)) {
			free(buf);
			return -1;
		}
		w->frame_count++;

		cur_pt += chunk_len;
		remaining -= chunk_len;
	}

	*out = buf;
	*out_len = out_off;
	return 0;
}

int aead_reader_init(struct aead_reader *r, const uint8_t key[AEAD_KEY_SIZE])
{
	if (!r || !key)
		return -1;
	memset(r, 0, sizeof(*r));
	memcpy(r->key, key, AEAD_KEY_SIZE);
	return 0;
}

void aead_reader_free(struct aead_reader *r)
{
	if (!r)
		return;
	free(r->ct_buf);
	free(r->pt_buf);
	memset(r, 0, sizeof(*r));
}

static int buf_append(uint8_t **buf, size_t *len, size_t *cap, const uint8_t *p, size_t n)
{
	if (*len + n > *cap) {
		size_t capn = *cap ? *cap * 2 : 4096;
		while (capn < *len + n)
			capn *= 2;
		uint8_t *nb = realloc(*buf, capn);
		if (!nb)
			return -1;
		*buf = nb;
		*cap = capn;
	}
	memcpy(*buf + *len, p, n);
	*len += n;
	return 0;
}

int aead_reader_feed(struct aead_reader *r, const uint8_t *ct, size_t ct_len)
{
	if (!r)
		return -1;
	if (ct && ct_len && buf_append(&r->ct_buf, &r->ct_len, &r->ct_cap, ct, ct_len) != 0)
		return -1;

	for (;;) {
		if (!r->header_read) {
			if (r->ct_len < AEAD_GCM_NONCE_SIZE)
				return 0;
			memcpy(r->nonce, r->ct_buf, AEAD_GCM_NONCE_SIZE);
			memcpy(r->stream_nonce, r->nonce, AEAD_GCM_NONCE_SIZE);
			memmove(r->ct_buf, r->ct_buf + AEAD_GCM_NONCE_SIZE,
				r->ct_len - AEAD_GCM_NONCE_SIZE);
			r->ct_len -= AEAD_GCM_NONCE_SIZE;
			r->header_read = 1;
		}
		if (r->ct_len < 4)
			return 0;
		uint32_t clen = ((uint32_t)r->ct_buf[0] << 24) | ((uint32_t)r->ct_buf[1] << 16) |
				((uint32_t)r->ct_buf[2] << 8) | (uint32_t)r->ct_buf[3];
		if (clen < AEAD_GCM_TAG_SIZE || clen > AEAD_MAX_PAYLOAD + AEAD_GCM_TAG_SIZE) {
			debug(LOG_ERR, "AEAD frame length %u invalid", clen);
			return -1;
		}
		if (r->ct_len < 4 + clen)
			return 0;

		uint8_t aad[AEAD_GCM_NONCE_SIZE + 4];
		memcpy(aad, r->stream_nonce, AEAD_GCM_NONCE_SIZE);
		memcpy(aad + AEAD_GCM_NONCE_SIZE, r->ct_buf, 4);

		uint8_t *pt = malloc(clen);
		if (!pt)
			return -1;
		size_t pt_len = 0;
		if (gcm_open(r->key, r->nonce, aad, sizeof(aad),
			     r->ct_buf + 4, clen, pt, &pt_len) != 0) {
			free(pt);
			debug(LOG_ERR, "AEAD decrypt failed");
			return -1;
		}
		memmove(r->ct_buf, r->ct_buf + 4 + clen, r->ct_len - 4 - clen);
		r->ct_len -= 4 + clen;
		if (buf_append(&r->pt_buf, &r->pt_len, &r->pt_cap, pt, pt_len) != 0) {
			free(pt);
			return -1;
		}
		free(pt);
		if (!increment_nonce(r->nonce, AEAD_GCM_NONCE_SIZE))
			return -1;
		r->frame_count++;
	}
}
