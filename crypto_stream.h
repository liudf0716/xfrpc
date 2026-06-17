// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Stream encryption (AES-128-CFB) and compression (Snappy) for proxy data.
 * Compatible with frp's use_encryption/use_compression protocol.
 */

#ifndef XFRPC_CRYPTO_STREAM_H
#define XFRPC_CRYPTO_STREAM_H

#include <stddef.h>
#include <stdint.h>

/* Opaque encryption context */
struct crypto_ctx;

/* Opaque snappy compression context */
struct snappy_ctx;

/**
 * @brief Derive AES-128 key from auth token using PBKDF2
 * @param token  Auth token string
 * @param out_key Output buffer (must be >= 16 bytes)
 * @return 0 on success, -1 on error
 */
int crypto_derive_key(const char *token, uint8_t *out_key);

/**
 * @brief Create encryption context for writing (encrypting)
 * @param key 16-byte AES key
 * @return Context pointer, or NULL on error. Caller must free with crypto_ctx_free()
 */
struct crypto_ctx *crypto_ctx_new_writer(const uint8_t *key);

/**
 * @brief Create encryption context for reading (decrypting)
 * @param key 16-byte AES key
 * @return Context pointer, or NULL on error. Caller must free with crypto_ctx_free()
 */
struct crypto_ctx *crypto_ctx_new_reader(const uint8_t *key);

/**
 * @brief Free encryption context
 */
void crypto_ctx_free(struct crypto_ctx *ctx);

/**
 * @brief Encrypt data in-place. Writer must call crypto_encrypt_init first.
 * @param ctx Writer context
 * @param data Data to encrypt (modified in-place)
 * @param len Length of data
 * @return 0 on success, -1 on error
 */
int crypto_encrypt(struct crypto_ctx *ctx, uint8_t *data, size_t len);

/**
 * @brief Decrypt data in-place. Reader must call crypto_decrypt_init first.
 * @param ctx Reader context
 * @param data Data to decrypt (modified in-place)
 * @param len Length of data
 * @return 0 on success, -1 on error
 */
int crypto_decrypt(struct crypto_ctx *ctx, uint8_t *data, size_t len);

/**
 * @brief Get the IV that was generated for writing (prepend to first write)
 * @param ctx Writer context
 * @param out_iv Output buffer (must be >= 16 bytes)
 * @return 0 on success, -1 if no IV available
 */
int crypto_get_iv(struct crypto_ctx *ctx, uint8_t *out_iv);

/**
 * @brief Set the IV for reading (from the first 16 bytes received)
 * @param ctx Reader context
 * @param iv 16-byte IV from the stream
 * @return 0 on success, -1 on error
 */
int crypto_set_iv(struct crypto_ctx *ctx, const uint8_t *iv);

/**
 * @brief Check if writer context has sent its IV
 */
int crypto_writer_iv_sent(struct crypto_ctx *ctx);

/**
 * @brief Mark that IV has been sent
 */
void crypto_writer_set_iv_sent(struct crypto_ctx *ctx);

/**
 * @brief Check if reader context has received its IV
 */
int crypto_reader_iv_received(struct crypto_ctx *ctx);

/**
 * @brief Mark that IV has been received
 */
void crypto_reader_set_iv_received(struct crypto_ctx *ctx);

/* ---- Snappy compression ---- */

/**
 * @brief Create snappy compression context
 */
struct snappy_ctx *snappy_ctx_new(void);

/**
 * @brief Free snappy context
 */
void snappy_ctx_free(struct snappy_ctx *ctx);

/**
 * @brief Compress data using snappy
 * @param ctx Snappy context
 * @param in Input data
 * @param in_len Input length
 * @param out Output buffer (caller must ensure足够大, snappy max = in_len + in_len/6 + 32)
 * @param out_len Output length (written by function)
 * @return 0 on success, -1 on error
 */
int snappy_compress_data(struct snappy_ctx *ctx, const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t *out_len);

/**
 * @brief Decompress data using snappy
 * @param ctx Snappy context
 * @param in Input data (snappy compressed)
 * @param in_len Input length
 * @param out Output buffer
 * @param out_buf_size Size of output buffer
 * @param out_len Output length (written by function)
 * @return 0 on success, -1 on error
 */
int snappy_decompress_data(struct snappy_ctx *ctx, const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_buf_size, size_t *out_len);

#endif /* XFRPC_CRYPTO_STREAM_H */
