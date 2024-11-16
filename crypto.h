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

/** @file crypto.h
    @brief xfrpc crypto header
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/


#ifndef XFRPC_CRYPTO_H
#define XFRPC_CRYPTO_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

/**
 * @brief Structure for FRP encryption/decryption operations
 */
struct frp_coder {
	uint8_t     key[16];    /**< Encryption/decryption key */
	char        *salt;      /**< Salt value for key derivation */
	uint8_t     iv[16];     /**< Initialization vector */
	char        *token;     /**< Authentication token */
};

/**
 * @brief Get the size of encryption block
 * @return Size of the encryption block
 */
size_t get_encrypt_block_size(void);

/**
 * @brief Decrypt data using the specified decoder
 * @param enc_data Encrypted data buffer
 * @param enc_len Length of encrypted data
 * @param decoder Decoder structure
 * @param ret Pointer to store decrypted data
 * @return Size of decrypted data
 */
size_t decrypt_data(const uint8_t *enc_data, size_t enc_len, struct frp_coder *decoder, uint8_t **ret);

/**
 * @brief Check if encoder is initialized
 * @return 1 if initialized, 0 otherwise
 */
int is_encoder_inited(void);

/**
 * @brief Check if decoder is initialized
 * @return 1 if initialized, 0 otherwise
 */
int is_decoder_inited(void);

/**
 * @brief Initialize main encoder
 * @return Pointer to initialized encoder structure
 */
struct frp_coder *init_main_encoder(void);

/**
 * @brief Initialize main decoder with given IV
 * @param iv Initialization vector
 * @return Pointer to initialized decoder structure
 */
struct frp_coder *init_main_decoder(const uint8_t *iv);

/**
 * @brief Create new coder with token and salt
 * @param token Authentication token
 * @param salt Salt for key derivation
 * @return Pointer to new coder structure
 */
struct frp_coder *new_coder(const char *token, const char *salt);

/**
 * @brief Encrypt key using token and salt
 * @param token Authentication token
 * @param token_len Token length
 * @param salt Salt value
 * @param key Key buffer
 * @param key_len Key length
 * @return Pointer to encrypted key
 */
uint8_t *encrypt_key(const char *token, size_t token_len, const char *salt, uint8_t *key, size_t key_len);

/**
 * @brief Encrypt initialization vector
 * @param iv_buf IV buffer
 * @param iv_len IV length
 * @return Pointer to encrypted IV
 */
uint8_t *encrypt_iv(uint8_t *iv_buf, size_t iv_len);

/**
 * @brief Encrypt data using specified encoder
 * @param src_data Source data buffer
 * @param srclen Source data length
 * @param encoder Encoder structure
 * @param ret Pointer to store encrypted data
 * @return Size of encrypted data
 */
size_t encrypt_data(const uint8_t *src_data, size_t srclen, struct frp_coder *encoder, uint8_t **ret);

/**
 * @brief Get main encoder instance
 * @return Pointer to main encoder
 */
struct frp_coder *get_main_encoder(void);

/**
 * @brief Get main decoder instance
 * @return Pointer to main decoder
 */
struct frp_coder *get_main_decoder(void);

/**
 * @brief Get block size
 * @return Block size value
 */
size_t get_block_size(void);

/**
 * @brief Free encoder structure
 * @param encoder Pointer to encoder structure
 */
void free_encoder(struct frp_coder *encoder);

/**
 * @brief Free EVP cipher context
 */
void free_crypto_resources(void);

#endif // XFRPC_CRYPTO_H
