// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Stream encryption (AES-128-CFB) and compression (Snappy) for proxy data.
 *
 * Encryption: AES-128-CFB stream cipher (compatible with frp use_encryption)
 *   Key derivation: PBKDF2(token, salt="frp", iter=64, keylen=16, SHA1)
 *   golib default salt is "crypto", but frps/frpc init() set
 *   crypto.DefaultSalt = "frp". Proxy data streams must use "frp".
 *   IV: 16 random bytes, prepended to first write
 *
 * Compression: Google Snappy (compatible with frp use_compression)
 *   Uses vendored snappy-c (Linux kernel version)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <event2/buffer.h>
#include "vendor/snappy/snappy.h"

#include "crypto_stream.h"
#include "debug.h"

#define AES_BLOCK_SIZE 16
#define PBKDF2_ITERATIONS 64
#define PBKDF2_SALT "frp"

/* ---- Encryption context ---- */

struct crypto_ctx {
	EVP_CIPHER_CTX *cipher_ctx;
	uint8_t key[AES_BLOCK_SIZE];
	uint8_t iv[AES_BLOCK_SIZE];
	int iv_sent;     /* for writer: has IV been prepended? */
	int iv_received; /* for reader: has IV been read? */
	int is_writer;
};

int crypto_derive_key(const char *token, uint8_t *out_key)
{
	if (!token || !out_key)
		return -1;

	/* PBKDF2(token, salt="frp", iter=64, keylen=16, SHA1) */
	if (PKCS5_PBKDF2_HMAC(token, strlen(token),
	                       (const unsigned char *)PBKDF2_SALT, strlen(PBKDF2_SALT),
	                       PBKDF2_ITERATIONS, EVP_sha1(),
	                       AES_BLOCK_SIZE, out_key) != 1) {
		debug(LOG_ERR, "PBKDF2 key derivation failed");
		return -1;
	}
	return 0;
}

struct crypto_ctx *crypto_ctx_new_writer(const uint8_t *key)
{
	struct crypto_ctx *ctx = calloc(1, sizeof(struct crypto_ctx));
	if (!ctx) return NULL;

	ctx->cipher_ctx = EVP_CIPHER_CTX_new();
	if (!ctx->cipher_ctx) {
		free(ctx);
		return NULL;
	}

	memcpy(ctx->key, key, AES_BLOCK_SIZE);
	ctx->is_writer = 1;

	/* Generate random IV */
	if (RAND_bytes(ctx->iv, AES_BLOCK_SIZE) != 1) {
		EVP_CIPHER_CTX_free(ctx->cipher_ctx);
		free(ctx);
		return NULL;
	}

	/* Initialize cipher with IV */
	if (EVP_EncryptInit_ex(ctx->cipher_ctx, EVP_aes_128_cfb128(), NULL, key, ctx->iv) != 1) {
		EVP_CIPHER_CTX_free(ctx->cipher_ctx);
		free(ctx);
		return NULL;
	}

	return ctx;
}

struct crypto_ctx *crypto_ctx_new_reader(const uint8_t *key)
{
	struct crypto_ctx *ctx = calloc(1, sizeof(struct crypto_ctx));
	if (!ctx) return NULL;

	ctx->cipher_ctx = EVP_CIPHER_CTX_new();
	if (!ctx->cipher_ctx) {
		free(ctx);
		return NULL;
	}

	memcpy(ctx->key, key, AES_BLOCK_SIZE);
	ctx->is_writer = 0;

	return ctx;
}

void crypto_ctx_free(struct crypto_ctx *ctx)
{
	if (!ctx) return;
	if (ctx->cipher_ctx) EVP_CIPHER_CTX_free(ctx->cipher_ctx);
	free(ctx);
}

int crypto_get_iv(struct crypto_ctx *ctx, uint8_t *out_iv)
{
	if (!ctx || !ctx->is_writer) return -1;
	memcpy(out_iv, ctx->iv, AES_BLOCK_SIZE);
	return 0;
}

int crypto_set_iv(struct crypto_ctx *ctx, const uint8_t *iv)
{
	if (!ctx || ctx->is_writer) return -1;

	/* Initialize cipher with received IV */
	if (EVP_DecryptInit_ex(ctx->cipher_ctx, EVP_aes_128_cfb128(), NULL, ctx->key, iv) != 1) {
		debug(LOG_ERR, "AES decrypt init failed");
		return -1;
	}

	ctx->iv_received = 1;
	return 0;
}

int crypto_writer_iv_sent(struct crypto_ctx *ctx)
{
	return ctx ? ctx->iv_sent : 0;
}

void crypto_writer_set_iv_sent(struct crypto_ctx *ctx)
{
	if (ctx) ctx->iv_sent = 1;
}

int crypto_reader_iv_received(struct crypto_ctx *ctx)
{
	return ctx ? ctx->iv_received : 0;
}

void crypto_reader_set_iv_received(struct crypto_ctx *ctx)
{
	if (ctx) ctx->iv_received = 1;
}

int crypto_encrypt(struct crypto_ctx *ctx, uint8_t *data, size_t len)
{
	if (!ctx || !ctx->is_writer || !data || len == 0) return -1;

	int outlen = 0;
	if (EVP_EncryptUpdate(ctx->cipher_ctx, data, &outlen, data, len) != 1) {
		debug(LOG_ERR, "AES encrypt failed");
		return -1;
	}
	return 0;
}

int crypto_decrypt(struct crypto_ctx *ctx, uint8_t *data, size_t len)
{
	if (!ctx || ctx->is_writer || !data || len == 0) return -1;

	int outlen = 0;
	if (EVP_DecryptUpdate(ctx->cipher_ctx, data, &outlen, data, len) != 1) {
		debug(LOG_ERR, "AES decrypt failed");
		return -1;
	}
	return 0;
}

/* ---- Snappy compression (compatible with frp) ---- */

int xfrpc_compress(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
	if (!in || !out || !out_len || in_len == 0) return -1;

	struct snappy_env env;
	if (snappy_init_env(&env) != 0) {
		debug(LOG_ERR, "snappy_init_env failed");
		return -1;
	}

	size_t comp_len = snappy_max_compressed_length(in_len);
	int ret = snappy_compress(&env, (const char *)in, in_len, (char *)out, &comp_len);
	snappy_free_env(&env);

	if (ret != 0) {
		debug(LOG_ERR, "snappy compress failed: %d", ret);
		return -1;
	}
	*out_len = comp_len;
	return 0;
}

int xfrpc_decompress(const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t out_buf_size, size_t *out_len)
{
	if (!in || !out || !out_len || in_len == 0) return -1;

	/* Get uncompressed size from snappy framing header */
	size_t uncomp_len = 0;
	if (!snappy_uncompressed_length((const char *)in, in_len, &uncomp_len)) {
		debug(LOG_ERR, "snappy_uncompressed_length failed");
		return -1;
	}

	if (uncomp_len > out_buf_size) {
		debug(LOG_ERR, "snappy decompress buffer too small: need %zu, have %zu",
		      uncomp_len, out_buf_size);
		return -1;
	}

	int ret = snappy_uncompress((const char *)in, in_len, (char *)out);
	if (ret != 0) {
		debug(LOG_ERR, "snappy decompress failed: %d", ret);
		return -1;
	}
	*out_len = uncomp_len;
	return 0;
}

/* ---- Snappy Framing Format (compatible with golang/snappy used by frp) ---- */

static uint32_t snappy_crc32c_masked(const uint8_t *data, size_t len)
{
	uint32_t crc = 0xffffffffU;
	for (size_t i = 0; i < len; i++) {
		crc ^= data[i];
		for (int b = 0; b < 8; b++) {
			crc = (crc >> 1) ^ ((crc & 1) ? 0x82f63b78U : 0U);
		}
	}
	crc ^= 0xffffffffU;
	return ((crc >> 15) | (crc << 17)) + 0xa282ead8U;
}

int xfrpc_snappy_frame_encode(const uint8_t *in, size_t in_len,
                              int *header_sent, struct evbuffer *dst)
{
	if (!in || !dst || in_len == 0) return -1;

	static const uint8_t stream_id[10] = {
		0xff, 0x06, 0x00, 0x00, 's', 'N', 'a', 'P', 'p', 'Y'
	};
	if (!header_sent || !*header_sent) {
		if (evbuffer_add(dst, stream_id, sizeof(stream_id)) != 0)
			return -1;
		if (header_sent)
			*header_sent = 1;
	}

	const size_t max_block = 65536;
	size_t offset = 0;
	while (offset < in_len) {
		size_t blk_len = in_len - offset;
		if (blk_len > max_block) blk_len = max_block;

		const uint8_t *blk = in + offset;
		uint32_t mcrc = snappy_crc32c_masked(blk, blk_len);

		size_t max_comp = snappy_max_compressed_length(blk_len);
		uint8_t *comp = malloc(max_comp);
		size_t comp_len = max_comp;
		int compressed = (comp && xfrpc_compress(blk, blk_len, comp, &comp_len) == 0 && comp_len < blk_len);

		uint8_t hdr[8];
		uint32_t payload_len = (uint32_t)(4 + (compressed ? comp_len : blk_len));
		hdr[0] = compressed ? 0x00 : 0x01;
		hdr[1] = (uint8_t)(payload_len & 0xff);
		hdr[2] = (uint8_t)((payload_len >> 8) & 0xff);
		hdr[3] = (uint8_t)((payload_len >> 16) & 0xff);
		hdr[4] = (uint8_t)(mcrc & 0xff);
		hdr[5] = (uint8_t)((mcrc >> 8) & 0xff);
		hdr[6] = (uint8_t)((mcrc >> 16) & 0xff);
		hdr[7] = (uint8_t)((mcrc >> 24) & 0xff);

		if (evbuffer_add(dst, hdr, sizeof(hdr)) != 0 ||
		    evbuffer_add(dst, compressed ? comp : blk, compressed ? comp_len : blk_len) != 0) {
			free(comp);
			return -1;
		}
		free(comp);
		offset += blk_len;
	}
	return 0;
}

int xfrpc_snappy_frame_decode(struct evbuffer *decomp_buf, struct evbuffer *dst)
{
	if (!decomp_buf || !dst) return -1;

	while (1) {
		size_t cur_len = evbuffer_get_length(decomp_buf);
		if (cur_len == 0)
			return 0;

		if (cur_len >= 10) {
			uint8_t magic[10];
			evbuffer_copyout(decomp_buf, magic, 10);
			if (magic[0] == 0xff && magic[1] == 0x06 && magic[2] == 0x00 && magic[3] == 0x00 &&
			    memcmp(magic + 4, "sNaPpY", 6) == 0) {
				evbuffer_drain(decomp_buf, 10);
				continue;
			}
		}

		if (cur_len < 4)
			return 0;

		uint8_t hdr[4];
		evbuffer_copyout(decomp_buf, hdr, 4);
		uint8_t type = hdr[0];
		uint32_t chunk_len = (uint32_t)hdr[1] | ((uint32_t)hdr[2] << 8) | ((uint32_t)hdr[3] << 16);

		if (chunk_len > 65536 + 4 || ((type == 0x00 || type == 0x01) && chunk_len < 4)) {
			debug(LOG_ERR, "Invalid snappy frame header: type=0x%02x len=%u", type, chunk_len);
			evbuffer_drain(decomp_buf, cur_len);
			return -1;
		}

		if (cur_len < 4 + (size_t)chunk_len)
			return 0;

		uint8_t *chunk = malloc(4 + (size_t)chunk_len);
		if (!chunk) return -1;
		evbuffer_remove(decomp_buf, chunk, 4 + (size_t)chunk_len);

		if (type == 0x00) {
			const uint8_t *cdata = chunk + 8;
			size_t clen = chunk_len - 4;
			size_t uncomp_len = 0;
			if (!snappy_uncompressed_length((const char *)cdata, clen, &uncomp_len) || uncomp_len == 0) {
				debug(LOG_ERR, "Snappy frame invalid uncompressed length");
				free(chunk);
				return -1;
			}
			uint8_t *uncomp = malloc(uncomp_len);
			if (!uncomp) {
				free(chunk);
				return -1;
			}
			if (snappy_uncompress((const char *)cdata, clen, (char *)uncomp) != 0) {
				debug(LOG_ERR, "Snappy frame decompression failed");
				free(uncomp);
				free(chunk);
				return -1;
			}
			evbuffer_add(dst, uncomp, uncomp_len);
			free(uncomp);
		} else if (type == 0x01) {
			if (chunk_len > 4)
				evbuffer_add(dst, chunk + 8, chunk_len - 4);
		} else if (type == 0xff || (type >= 0x80 && type <= 0xfd)) {
			/* Stream identifier or skippable chunk */
		} else {
			debug(LOG_ERR, "Unsupported unskippable snappy chunk type 0x%02x", type);
			free(chunk);
			return -1;
		}
		free(chunk);
	}
}
