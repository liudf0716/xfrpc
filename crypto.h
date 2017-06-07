#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct frp_coder {
	unsigned char 	*key;
	ushort 			key_len;
	char 			*salt;
	unsigned char 	*iv;
	char 			*privilege_token;
};

size_t get_encrypt_block_size();
size_t decrypt_data();
int is_encoder_inited();
int is_decoder_inited();
struct frp_coder *init_main_encoder();
struct frp_coder *init_main_decoder(unsigned char *iv);
struct frp_coder *new_coder(const char *privilege_token, const char *salt);
unsigned char *encrypt_key(const char *token, size_t token_len, const char *salt);
unsigned char *encrypt_iv(unsigned char *iv_buf, size_t iv_len);
size_t encrypt_data(const unsigned char *src_data, size_t srclen, struct frp_coder *encoder, unsigned char **ret);
struct frp_coder *get_main_encoder();
struct frp_coder *get_main_decoder();
size_t get_block_size();

#endif // _CRYPTO_H_