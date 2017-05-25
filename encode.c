#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "fastpbkdf2.h"
#include "encode.h"
#include "config.h"

static const char *default_salt = "frp";
static struct frp_encoder *main_encoder = NULL;

struct frp_encoder *new_encoder(const char *privilege_token, const char *salt)
{
	struct frp_encoder *enc = calloc(sizeof(struct frp_encoder), 1);
	assert(enc);

	enc->privilege_token = strdup(privilege_token);
	enc->key_len = 16;
	enc->salt = strdup(salt);
	enc->key = encrypt_key(enc->privilege_token, strlen(enc->privilege_token), enc->salt);
	return enc;
}

struct frp_encoder *init_main_encoder() {
	
	struct common_conf *c_conf = get_common_config();
	main_encoder = new_encoder(c_conf->privilege_token, default_salt);
	assert(main_encoder);
	assert(main_encoder->key);

	return main_encoder;
}

struct frp_encoder *get_main_encoder() 
{
	return main_encoder;
}

// 29 201 136 254 206 150 233 65 13 82 120 149 203 228 122 128 
// key_ret buffer len must be 16
// the result of key should be free after using
char *encrypt_key(const char *token, size_t token_len, const char *salt) 
{
	char out[17] = {0};

	fastpbkdf2_hmac_sha1((void *)token, 
						token_len, (void *)salt, 
						strlen(salt), 
						64, 
						(void *)out, 
						16);
	
	/* debug */
	printf("KYYYYYYYYYYYYY=");
	int i = 0;
	for(i=0; i<16; i++ ) {
		printf("%d ", (unsigned char) *((char *)out + i));
	}

	printf("\n");
	/* debug end */

	char *key_ret = calloc(16, 1);
	if (! key_ret)
		fprintf(stderr, "key result buffer not applied!\n");
	else
		memcpy(key_ret, out, 16);
	
	return key_ret;
}

char *encrypt_data(char *src_data, size_t srlen)
{
	struct common_conf *c_conf = get_common_config();

	return NULL;
}

void free_encoder(struct frp_encoder *encoder) {
	if (encoder) {
		SAFE_FREE(encoder->privilege_token);
		SAFE_FREE(encoder->salt);
		SAFE_FREE(encoder->key);
		SAFE_FREE(encoder);
	}
}