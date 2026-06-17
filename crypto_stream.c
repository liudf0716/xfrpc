// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Stream encryption (AES-128-CFB) and compression (Snappy) for proxy data.
 * Compatible with frp's use_encryption/use_compression protocol.
 *
 * Encryption: AES-128-CFB stream cipher
 *   Key derivation: PBKDF2(token, salt="crypto", iter=64, keylen=16, SHA1)
 *   IV: 16 random bytes, prepended to first write
 *
 * Compression: Google Snappy framing format
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#ifdef HAS_SNAPPY
#include <snappy-c.h>
#endif

#include "crypto_stream.h"
#include "debug.h"

#define AES_BLOCK_SIZE 16
#define PBKDF2_ITERATIONS 64
#define PBKDF2_SALT "crypto"

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

	/* PBKDF2(token, salt="crypto", iter=64, keylen=16, SHA1) */
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

/* ---- Snappy compression ---- */

#ifdef HAS_SNAPPY

struct snappy_ctx {
	/* snappy-c uses stateless functions, no persistent state needed */
	int placeholder;
};

struct snappy_ctx *snappy_ctx_new(void)
{
	struct snappy_ctx *ctx = calloc(1, sizeof(struct snappy_ctx));
	return ctx;
}

void snappy_ctx_free(struct snappy_ctx *ctx)
{
	free(ctx);
}

int snappy_compress_data(struct snappy_ctx *ctx, const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t *out_len)
{
	(void)ctx;
	if (!in || !out || !out_len || in_len == 0) return -1;

	size_t max_out = snappy_max_compressed_length(in_len);
	snappy_status status = snappy_compress((const char *)in, in_len, (char *)out, &max_out);
	if (status != SNAPPY_OK) {
		debug(LOG_ERR, "Snappy compress failed: %d", status);
		return -1;
	}
	*out_len = max_out;
	return 0;
}

int snappy_decompress_data(struct snappy_ctx *ctx, const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_buf_size, size_t *out_len)
{
	(void)ctx;
	if (!in || !out || !out_len || in_len == 0) return -1;

	size_t uncompressed_len = 0;
	snappy_status status = snappy_uncompressed_length((const char *)in, in_len, &uncompressed_len);
	if (status != SNAPPY_OK) {
		debug(LOG_ERR, "Snappy uncompressed_length failed: %d", status);
		return -1;
	}

	if (uncompressed_len > out_buf_size) {
		debug(LOG_ERR, "Snappy decompress buffer too small: need %zu, have %zu",
		      uncompressed_len, out_buf_size);
		return -1;
	}

	status = snappy_uncompress((const char *)in, in_len, (char *)out, &uncompressed_len);
	if (status != SNAPPY_OK) {
		debug(LOG_ERR, "Snappy decompress failed: %d", status);
		return -1;
	}
	*out_len = uncompressed_len;
	return 0;
}

#endif /* HAS_SNAPPY */
