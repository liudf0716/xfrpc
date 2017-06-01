#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct frp_encoder {
	unsigned char 	*key;
	ushort 			key_len;
	char 			*salt;
	unsigned char 	*iv;
	char 			*privilege_token;
};

struct frp_encoder *init_main_encoder();
struct frp_encoder *new_encoder(const char *privilege_token, const char *salt);
unsigned char *encrypt_key(const char *token, size_t token_len, const char *salt);
unsigned char *encrypt_iv();
char *encrypt_data(char *src_data, size_t srlen);
struct frp_encoder *get_main_encoder();
struct frp_encoder *new_encoder(const char *privilege_token, const char *salt);

#endif // _CRYPTO_H_