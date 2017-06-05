#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include "fastpbkdf2.h"
#include "crypto.h"
#include "config.h"

static const char *default_salt = "frp";
static const size_t block_size = 16;
static struct frp_coder *main_encoder = NULL;
static struct frp_coder *main_decoder = NULL;

size_t get_block_size()
{
	return block_size;
}

// TODO: NEED free
struct frp_coder *new_coder(const char *privilege_token, const char *salt)
{
	struct frp_coder *enc = calloc(sizeof(struct frp_coder), 1);
	assert(enc);

	enc->privilege_token = strdup(privilege_token);
	enc->key_len = block_size;
	enc->salt = strdup(salt);
	enc->key = encrypt_key(enc->privilege_token, strlen(enc->privilege_token), enc->salt);
	enc->iv = calloc(block_size, 1);
	encrypt_iv(enc->iv, block_size);
	return enc;
}

size_t get_encrypt_block_size()
{
	return block_size;
}

struct frp_coder *init_main_encoder() 
{
	struct common_conf *c_conf = get_common_config();
	main_encoder = new_coder(c_conf->privilege_token, default_salt);
	assert(main_encoder);
	assert(main_encoder->key);

	return main_encoder;
}

struct frp_coder *init_main_decoder(unsigned char *iv)
{
	struct common_conf *c_conf = get_common_config();
	main_decoder = new_coder(c_conf->privilege_token, default_salt);
	assert(main_encoder);
	assert(main_encoder->key);
	memcpy(main_decoder->iv, iv, block_size);

	return main_decoder;
}

struct frp_coder *get_main_encoder() 
{
	return main_encoder;
}

struct frp_coder *get_main_decoder()
{
	return main_decoder;
}

int is_encoder_inited()
{
	struct frp_coder *e = get_main_encoder();
	return e != NULL;
}

int is_decoder_inited()
{
	struct frp_coder *d = get_main_decoder();
	return d != NULL;
}
// 29 201 136 254 206 150 233 65 13 82 120 149 203 228 122 128 
// key_ret buffer len must be 16
// the result should be free after using
unsigned char *encrypt_key(const char *token, size_t token_len, const char *salt) 
{
	unsigned char *key_ret = calloc(block_size, 1);
	fastpbkdf2_hmac_sha1((void *)token, 
						token_len, (void *)salt, 
						strlen(salt), 
						64, 
						(void *)key_ret, 
						block_size);
	
	/* debug */
	printf("encrypt_key = ");
	int i = 0;
	for(i=0; i<block_size; i++ ) {
		printf("%d ", *(key_ret + i));
	}

	printf("\n");
	/* debug end */
	
	if (! key_ret)
		fprintf(stderr, "key result buffer not applied!\n");
	
	return key_ret;
}

// the result should be free after using
unsigned char *encrypt_iv(unsigned char *iv_buf, size_t iv_len)
{
	if (iv_len < block_size || iv_buf == NULL) {
		return NULL;
	}

	size_t i;
	srand((unsigned int) time(NULL));

	for(i=0; i<iv_len; i++) {
		iv_buf[i] = (rand() % 254 ) + 1;

		//test:
		iv_buf[i] = 99;
		printf("iv[%ld]=%d ", i, iv_buf[i]);
	}

	printf("\n");
	return iv_buf;
}

// TODO:NEED free
char *encrypt_data(char *src_data, size_t srlen)
{
	char *ret_buf = calloc(srlen, 1);
	
	return NULL;
}

void free_encoder(struct frp_coder *encoder) {
	if (encoder) {
		SAFE_FREE(encoder->privilege_token);
		SAFE_FREE(encoder->salt);
		SAFE_FREE(encoder->key);
		SAFE_FREE(encoder->iv);
		SAFE_FREE(encoder);
	}
}

/*
login:

[1 2 182 0 3 0 0 0 111 0 0 0 0 0 0 0 173 123 34 118 101 114 115 105 111 110 34 58 34 48 46 49 48 46 48 34 44 34 104 111 115 116 110 97 109 101 34 58 34 34 44 34 111 115 34 58 34 108 105 110 117 120 34 44 34 97 114 99 104 34 58 34 97 109 100 54 52 34 44 34 117 115 101 114 34 58 34 34 44 34 112 114 105 118 105 108 101 103 101 95 107 101 121 34 58 34 48 99 50 48 55 57 57 53 102 100 99 48 55 48 52 97 53 51 53 100 98 98 51 51 51 53 51 54 99 49 97 99 34 44 34 116 105 109 101 115 116 97 109 112 34 58 49 52 57 54 50 57 55 49 49 57 44 34 114 117 110 95 105 100 34 58 34 34 44 34 112 111 111 108 95 99 111 117 110 116 34 58 49 125 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]

recv:

[1 2 68 0 3 0 0 0 49 0 0 0 0 0 0 0 59 123 34 118 101 114 115 105 111 110 34 58 34 48 46 49 48 46 48 34 44 34 114 117 110 95 105 100 34 58 34 98 53 54 97 101 51 57 101 52 52 53 48 99 51 97 51 34 44 34 101 114 114 111 114 34 58 34 34 125]

lgoin confirm:
[1 2 16 0 3 0 0 0 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 111 110 34 58 34 48 46 49 48 46 48 34 44 34 104 111 115 116 110 97 109 101 34 58]

recv:
[1 2 16 0 3 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 111 110 34 58 34 48 46 49 48 46 48 34 44 34 114 117 110 95 105 100 34 58 34 100]

*/