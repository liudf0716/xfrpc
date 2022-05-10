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
	char 		*privilege_token;
};

size_t get_encrypt_block_size();
size_t decrypt_data(const uint8_t *enc_data, size_t enc_len, struct frp_coder *decoder, uint8_t **ret);
int is_encoder_inited();
int is_decoder_inited();
struct frp_coder *init_main_encoder();
struct frp_coder *init_main_decoder(const uint8_t *iv);
struct frp_coder *new_coder(const char *privilege_token, const char *salt);
uint8_t *encrypt_key(const char *token, size_t token_len, const char *salt, uint8_t *key, size_t key_len);
uint8_t *encrypt_iv(uint8_t *iv_buf, size_t iv_len);
size_t encrypt_data(const uint8_t *src_data, size_t srclen, struct frp_coder *encoder, uint8_t **ret);
struct frp_coder *get_main_encoder();
struct frp_coder *get_main_decoder();
size_t get_block_size();
void free_encoder(struct frp_coder *encoder);

#endif // _CRYPTO_H_
