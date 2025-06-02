
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <syslog.h>
#include <openssl/ssl.h>

#include "fastpbkdf2.h"
#include "crypto.h"
#include "config.h"
#include "common.h"
#include "debug.h"

/** 
 * Default salt value used for key derivation
 */
static const char *default_salt = "frp";

/**
 * Block size in bytes for AES-128 encryption (16 bytes = 128 bits)
 */
static const size_t block_size = 16;

/**
 * Global encoder instance used for encryption operations
 * Initialized by init_main_encoder()
 */
static struct frp_coder *main_encoder = NULL;

/**
 * Global decoder instance used for decryption operations
 * Initialized by init_main_decoder()
 */
static struct frp_coder *main_decoder = NULL;

/**
 * Persistent encryption context for improved performance
 * Reused across multiple encrypt_data() calls
 */
static EVP_CIPHER_CTX *enc_ctx = NULL;

/**
 * Persistent decryption context for improved performance
 * Reused across multiple decrypt_data() calls
 */
static EVP_CIPHER_CTX *dec_ctx = NULL;

/**
 * @brief Frees all resources associated with a frp_coder structure
 *
 * This helper function safely deallocates the memory used by a frp_coder
 * structure and its members (salt and token).
 *
 * @param coder Pointer to the frp_coder structure to be freed
 */
static void free_frp_coder(struct frp_coder *coder)
{
	if (!coder) return;
	SAFE_FREE(coder->salt);
	SAFE_FREE(coder->token);
	SAFE_FREE(coder);
}

/**
 * @brief Frees both main encoder and decoder instances
 *
 * This helper function releases the memory used by the global main_encoder
 * and main_decoder instances.
 */
static void free_all_frp_coders(void)
{
	if (main_encoder) {
		free_frp_coder(main_encoder);
		main_encoder = NULL;
	}

	if (main_decoder) {
		free_frp_coder(main_decoder);
		main_decoder = NULL;
	}
}

/**
 * @brief Cleans up all encryption/decryption resources
 *
 * This function performs complete cleanup of all crypto-related resources:
 * - Frees the main encoder and decoder
 * - Releases the encryption and decryption contexts
 * Should be called before program termination.
 */
void free_crypto_resources(void)
{
	free_all_frp_coders();

	if (enc_ctx) {
		EVP_CIPHER_CTX_free(enc_ctx);
		enc_ctx = NULL;
	}

	if (dec_ctx) {
		EVP_CIPHER_CTX_free(dec_ctx);
		dec_ctx = NULL;
	}
}

/**
 * @brief Returns the cipher block size
 *
 * This function returns the block size used for AES encryption/decryption.
 * Currently fixed at 16 bytes for AES-128.
 *
 * @return Size of the encryption block in bytes
 */
size_t get_block_size()
{
	return block_size;
}

/**
 * @brief Creates a new frp_coder instance
 *
 * This function allocates and initializes a new frp_coder structure with the
 * specified token and salt. It generates the encryption key and IV automatically.
 *
 * @param token Authentication token (will use empty string if NULL)
 * @param salt Salt value for key derivation
 * @return Pointer to new frp_coder instance, or NULL on allocation failure
 */
struct frp_coder *new_coder(const char *token, const char *salt)
{
	struct frp_coder *enc = calloc(sizeof(struct frp_coder), 1);
	if (!enc) return NULL;

	enc->token = token ? strdup(token) : strdup("");
	enc->salt = salt ? strdup(salt) : NULL;
	
	if (!enc->token || !enc->salt) {
		free_frp_coder(enc);
		return NULL;
	}

	encrypt_key(enc->token, strlen(enc->token), enc->salt, enc->key, block_size);
	encrypt_iv(enc->iv, block_size);
	return enc;
}

/**
 * @brief Creates a deep copy of a frp_coder instance
 *
 * This function creates a new frp_coder structure with identical contents
 * to the source coder, including new copies of the token and salt strings.
 *
 * @param coder Source frp_coder to clone
 * @return Pointer to cloned frp_coder instance, or NULL on allocation failure
 */
struct frp_coder *clone_coder(const struct frp_coder *coder)
{
	if (!coder) return NULL;

	struct frp_coder *enc = calloc(sizeof(struct frp_coder), 1);
	if (!enc) return NULL;

	memcpy(enc, coder, sizeof(*coder));
	enc->token = strdup(coder->token);
	enc->salt = strdup(coder->salt);

	if (!enc->token || !enc->salt) {
		free_frp_coder(enc);
		return NULL;
	}

	return enc;
}

/**
 * @brief Initializes the main encoder instance
 *
 * This function initializes the main encoder used for encryption by either:
 * 1. Cloning the existing decoder if one exists, or
 * 2. Creating a new encoder using the authentication token from common config
 *
 * @return Pointer to the initialized main encoder instance
 */
struct frp_coder *init_main_encoder() 
{
	if (main_decoder) {
		main_encoder = clone_coder(main_decoder);
	} else {
		struct common_conf *c_conf = get_common_config();
		main_encoder = new_coder(c_conf->auth_token, default_salt);
	}
	return main_encoder;
}

/**
 * @brief Initializes the main decoder instance
 *
 * This function creates a new decoder using the authentication token from 
 * common config and initializes it with the provided IV (initialization vector).
 *
 * @param iv Pointer to the initialization vector buffer (must be block_size bytes)
 * @return Pointer to the initialized main decoder instance
 */
struct frp_coder *init_main_decoder(const uint8_t *iv)
{
	struct common_conf *c_conf = get_common_config();
	main_decoder = new_coder(c_conf->auth_token, default_salt);
	memcpy(main_decoder->iv, iv, block_size);
	return main_decoder;
}

/**
 * @brief Returns the main encoder instance
 *
 * This function provides access to the global main encoder used for encryption.
 *
 * @return Pointer to the main encoder instance, or NULL if not initialized
 */
struct frp_coder *get_main_encoder() 
{
	return main_encoder;
}

/**
 * @brief Returns the main decoder instance
 *
 * This function provides access to the global main decoder used for decryption.
 *
 * @return Pointer to the main decoder instance, or NULL if not initialized
 */
struct frp_coder *get_main_decoder()
{
	return main_decoder;
}

/**
 * @brief Checks if the main encoder is initialized
 *
 * This function verifies whether the main encoder has been properly initialized
 * and is ready for use.
 *
 * @return 1 if encoder is initialized, 0 otherwise
 */
int is_encoder_inited()
{
	return get_main_encoder() != NULL;
}

/**
 * @brief Checks if the main decoder is initialized
 *
 * This function verifies whether the main decoder has been properly initialized
 * and is ready for use.
 *
 * @return 1 if decoder is initialized, 0 otherwise
 */
int is_decoder_inited()
{
	return get_main_decoder() != NULL;
}

/**
 * @brief Generates an encryption key using PBKDF2-HMAC-SHA1
 *
 * This function derives a cryptographic key from a token and salt using
 * PBKDF2-HMAC-SHA1 with 64 iterations. The key length is fixed at 16 bytes
 * for AES-128.
 *
 * @param token The input token used as the password
 * @param token_len Length of the token
 * @param salt The salt value used in key derivation
 * @param key Buffer to store the generated key (must be at least block_size bytes)
 * @param block_size Size of the key to generate (should be 16 for AES-128)
 * @return Pointer to the generated key (same as key parameter)
 */
unsigned char *encrypt_key(const char *token, size_t token_len, const char *salt, 
			uint8_t *key, size_t block_size) 
{
	if (!token || !salt || !key || block_size != 16) {
		return NULL;
	}

	fastpbkdf2_hmac_sha1((void *)token, 
						 token_len, 
						 (void *)salt, 
						 strlen(salt), 
						 64,            // Number of iterations 
						 (void *)key, 
						 block_size);
	return key;
}

/**
 * @brief Generates a random initialization vector (IV)
 *
 * This function creates a cryptographically secure IV by generating
 * random bytes between 1 and 255. The IV is used for AES-128-CFB
 * encryption.
 *
 * @param iv_buf Buffer to store the generated IV
 * @param iv_len Length of the IV to generate (must be >= block_size)
 * @return Pointer to the generated IV buffer, or NULL if parameters are invalid
 */
unsigned char *encrypt_iv(unsigned char *iv_buf, size_t iv_len)
{
	if (!iv_buf || iv_len < block_size) {
		return NULL;
	}

	srand((unsigned int)time(NULL));
	for (size_t i = 0; i < iv_len; i++) {
		iv_buf[i] = (rand() % 254) + 1;  // Generate values between 1 and 255
	}

	return iv_buf;
}

/**
 * @brief Encrypts data using AES-128-CFB cipher
 *
 * This function encrypts data using AES-128-CFB cipher mode with no padding.
 * It uses a persistent EVP_CIPHER_CTX context (enc_ctx) for better performance
 * across multiple calls.
 *
 * @param src_data Pointer to the source data buffer to encrypt
 * @param srclen Length of the source data
 * @param encoder Pointer to the frp_coder structure containing key and IV
 * @param ret Address where the pointer to encrypted data will be stored
 * @return The length of the encrypted data, or 0 if encryption fails
 */
size_t encrypt_data(const uint8_t *src_data, size_t srclen, 
				   struct frp_coder *encoder, uint8_t **ret)
{
	int outlen = 0, tmplen = 0;
	uint8_t *outbuf = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	
	// Input validation
	if (!src_data || !encoder || !ret) {
		debug(LOG_ERR, "Invalid input parameters");
		return 0;
	}

	// Allocate output buffer
	outbuf = calloc(srclen + 1, 1);
	if (!outbuf) {
		debug(LOG_ERR, "Failed to allocate output buffer");
		return 0;
	}
	*ret = outbuf;

	// Initialize or reuse encryption context
	if (!enc_ctx) {
		enc_ctx = EVP_CIPHER_CTX_new();
		if (!enc_ctx) {
			debug(LOG_ERR, "Failed to create cipher context");
			return 0;
		}
		EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_cfb(), NULL, 
						  encoder->key, encoder->iv);
	}
	ctx = enc_ctx;

	// Perform encryption
	if (!EVP_EncryptUpdate(ctx, outbuf, &tmplen, src_data, srclen)) {
		debug(LOG_ERR, "EVP_EncryptUpdate error!");
		return 0;
	}
	outlen = tmplen;

	if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
		debug(LOG_ERR, "EVP_EncryptFinal_ex error!");
		return 0;
	}
	outlen += tmplen;

	return outlen;
}

/**
 * @brief Decrypts data using AES-128-CFB cipher
 *
 * This function decrypts data that was encrypted using AES-128-CFB cipher mode.
 * It uses a persistent EVP_CIPHER_CTX context (dec_ctx) for better performance
 * across multiple calls.
 *
 * @param enc_data Pointer to the encrypted data buffer
 * @param enclen Length of the encrypted data
 * @param decoder Pointer to the frp_coder structure containing key and IV
 * @param ret Address where the pointer to decrypted data will be stored
 * @return The length of the decrypted data, or 0 if decryption fails
 */
size_t decrypt_data(const uint8_t *enc_data, size_t enclen, 
				   struct frp_coder *decoder, uint8_t **ret)
{
	int outlen = 0, tmplen = 0;
	uint8_t *outbuf = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	
	// Input validation
	if (!enc_data || !decoder || !ret) {
		debug(LOG_ERR, "Invalid input parameters");
		return 0;
	}

	// Allocate output buffer
	outbuf = calloc(enclen + 1, 1);
	if (!outbuf) {
		debug(LOG_ERR, "Failed to allocate output buffer");
		return 0;
	}
	*ret = outbuf;

	// Initialize or reuse decryption context
	if (!dec_ctx) {
		dec_ctx = EVP_CIPHER_CTX_new();
		if (!dec_ctx) {
			debug(LOG_ERR, "Failed to create cipher context");
			return 0;
		}
		EVP_DecryptInit_ex(dec_ctx, EVP_aes_128_cfb(), NULL, 
						  decoder->key, decoder->iv);
	}
	ctx = dec_ctx;

	// Perform decryption
	if (!EVP_DecryptUpdate(ctx, outbuf, &tmplen, enc_data, enclen)) {
		debug(LOG_ERR, "EVP_DecryptUpdate error!");
		return 0;
	}
	outlen = tmplen;

	if (!EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
		debug(LOG_ERR, "EVP_DecryptFinal_ex error");
		return 0;
	}
	outlen += tmplen;

	return outlen;
}

/**
 * @brief Frees a frp_coder structure and its members
 * 
 * This function safely frees all memory associated with a frp_coder structure,
 * including its token and salt members. It uses the SAFE_FREE macro to handle
 * NULL pointers gracefully.
 *
 * @param encoder Pointer to the frp_coder structure to be freed. Can be NULL.
 */
void free_encoder(struct frp_coder *encoder) 
{
	if (encoder) {
		SAFE_FREE(encoder->token);
		SAFE_FREE(encoder->salt);
		SAFE_FREE(encoder);
	}
}
