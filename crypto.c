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

struct frp_coder *
init_main_encoder() 
{
	if (main_decoder) {
		main_encoder = clone_coder(main_decoder);
	} else {
		struct common_conf *c_conf = get_common_config();
		main_encoder = new_coder(c_conf->auth_token, default_salt);
	}
	return main_encoder;
}

struct frp_coder *
init_main_decoder(const uint8_t *iv)
{
	struct common_conf *c_conf = get_common_config();
	main_decoder = new_coder(c_conf->auth_token, default_salt);
	memcpy(main_decoder->iv, iv, block_size);
	return main_decoder;
}

struct frp_coder *
get_main_encoder() 
{
	return main_encoder;
}

struct frp_coder *
get_main_decoder()
{
	return main_decoder;
}

int 
is_encoder_inited()
{
	struct frp_coder *e = get_main_encoder();
	return e != NULL;
}

int 
is_decoder_inited()
{
	struct frp_coder *d = get_main_decoder();
	return d != NULL;
}

// key_ret buffer len must be 16
// the result should be free after using
unsigned char *
encrypt_key(const char *token, size_t token_len, const char *salt, uint8_t *key, size_t block_size) 
{
	unsigned char *key_ret = key;
	fastpbkdf2_hmac_sha1((void *)token, 
						token_len, (void *)salt, 
						strlen(salt), 
						64, 
						(void *)key_ret, 
						block_size);
	return key_ret;
}

// the result should be free after using
unsigned char *
encrypt_iv(unsigned char *iv_buf, size_t iv_len)
{
	if (iv_len < block_size || iv_buf == NULL) {
		return NULL;
	}

	srand((unsigned int) time(NULL));
	for(size_t i=0; i<iv_len; i++) {
		iv_buf[i] = (rand() % 254 ) + 1;
	}

	return iv_buf;
}

// using aes-128-cfb and nopadding
size_t 
encrypt_data(const uint8_t *src_data, size_t srclen, struct frp_coder *encoder, unsigned char **ret)
{
	uint8_t *intext = (uint8_t *)src_data;
	assert(intext);
	assert(encoder);
	struct frp_coder *c = encoder;
	int outlen = 0, tmplen = 0;
	uint8_t *outbuf = NULL;
	assert(c);

	outbuf = calloc(srclen, 1);
	assert(outbuf);
	*ret = outbuf;

	if (!enc_ctx) {
		enc_ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_cfb(), NULL, c->key, c->iv);
	}
	EVP_CIPHER_CTX *ctx = enc_ctx;

	if(!EVP_EncryptUpdate(ctx, outbuf, &tmplen, intext, (int)srclen)) {
		debug(LOG_ERR, "EVP_EncryptUpdate error!");
		goto E_END;
	}
	outlen += tmplen;
	if(!EVP_EncryptFinal_ex(ctx, outbuf+tmplen, &tmplen)) {
		debug(LOG_ERR, "EVP_EncryptFinal_ex error!");
		goto E_END;
	}

	outlen += tmplen;
E_END:
	return outlen;
}

size_t 
decrypt_data(const uint8_t *enc_data, size_t enclen, struct frp_coder *decoder, uint8_t **ret)
{
	uint8_t *inbuf = (uint8_t *)enc_data;
	uint8_t *outbuf = calloc(enclen+1, 1);
	struct frp_coder *c = decoder;
	assert(inbuf);
	assert(outbuf);
	*ret = outbuf;
	assert(decoder);
	
	int outlen = 0, tmplen = 0;
	if (!dec_ctx) {
		dec_ctx= EVP_CIPHER_CTX_new();
		EVP_DecryptInit_ex(dec_ctx, EVP_aes_128_cfb(), NULL, c->key, c->iv);
	}

	EVP_CIPHER_CTX *ctx = dec_ctx;
	if(!EVP_DecryptUpdate(ctx, outbuf, &tmplen, inbuf, enclen)) {
		debug(LOG_ERR, "EVP_DecryptUpdate error!");
		goto D_END;
	}
	outlen += tmplen;

	if(!EVP_DecryptFinal_ex(ctx, outbuf+outlen, &tmplen)) {
		debug(LOG_ERR, "EVP_DecryptFinal_ex error");
		goto D_END;
	}
	outlen += tmplen;

D_END:
	return outlen;
}

void 
free_encoder(struct frp_coder *encoder) {
	if (encoder) {
		SAFE_FREE(encoder->token);
		SAFE_FREE(encoder->salt);
		free(encoder);
	}
}
