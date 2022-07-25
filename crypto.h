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


#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

struct frp_coder {
	uint8_t 	key[16];
	char 		*salt;
	uint8_t 	iv[16];
	char 		*token;
};

size_t get_encrypt_block_size();
size_t decrypt_data(const uint8_t *enc_data, size_t enc_len, struct frp_coder *decoder, uint8_t **ret);
int is_encoder_inited();
int is_decoder_inited();
struct frp_coder *init_main_encoder();
struct frp_coder *init_main_decoder(const uint8_t *iv);
struct frp_coder *new_coder(const char *token, const char *salt);
uint8_t *encrypt_key(const char *token, size_t token_len, const char *salt, uint8_t *key, size_t key_len);
uint8_t *encrypt_iv(uint8_t *iv_buf, size_t iv_len);
size_t encrypt_data(const uint8_t *src_data, size_t srclen, struct frp_coder *encoder, uint8_t **ret);
struct frp_coder *get_main_encoder();
struct frp_coder *get_main_decoder();
size_t get_block_size();
void free_encoder(struct frp_coder *encoder);
void free_evp_cipher_ctx();

#endif // _CRYPTO_H_
