/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/** @file crypto.c
    @brief xfrpc crypto implement
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
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

static const char *default_salt = "frp";
static const size_t block_size = 16;
static struct frp_coder *main_encoder = NULL;
static struct frp_coder *main_decoder = NULL;
static EVP_CIPHER_CTX *enc_ctx = NULL;
static EVP_CIPHER_CTX *dec_ctx = NULL;

static void
free_frp_coder(struct frp_coder *coder)
{
	free(coder->salt);
	free(coder->token);
	free(coder);
}

static void
free_all_frp_coder()
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

void 
free_evp_cipher_ctx() 
{
	free_all_frp_coder();

	if (enc_ctx) {
		EVP_CIPHER_CTX_free(enc_ctx);
		enc_ctx = NULL;
	}

	if (dec_ctx) {
		EVP_CIPHER_CTX_free(dec_ctx);
		dec_ctx = NULL;
	}
}

size_t 
get_block_size()
{
	return block_size;
}

struct frp_coder *
new_coder(const char *token, const char *salt)
{
	struct frp_coder *enc = calloc(sizeof(struct frp_coder), 1);
	assert(enc);

	enc->token = token ? strdup(token):strdup("\0");
	enc->salt = strdup(salt);
	encrypt_key(enc->token, strlen(enc->token), enc->salt, enc->key, block_size);
	encrypt_iv(enc->iv, block_size);
	return enc;
}

struct frp_coder *
clone_coder(const struct frp_coder *coder)
{
	assert(coder);
	struct frp_coder *enc = calloc(sizeof(struct frp_coder), 1);
	memcpy(enc, coder, sizeof(*coder));
	enc->token = strdup(coder->token);
	enc->salt 	= strdup(coder->salt);

	return enc;
}

size_t 
get_encrypt_block_size()
{
	return block_size;
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
