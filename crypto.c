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

// #define ENC_DEBUG 1

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

	enc->privilege_token = privilege_token ? strdup(privilege_token):"\0";
	assert(enc->privilege_token);
	enc->key_len = block_size;
	enc->salt = strdup(salt);
	assert(enc->salt);
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
	main_encoder = new_coder(c_conf->auth_token, default_salt);
	return main_encoder;
}

struct frp_coder *init_main_decoder(unsigned char *iv)
{
	struct common_conf *c_conf = get_common_config();
	main_decoder = new_coder(c_conf->auth_token, default_salt);
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
#ifdef ENC_DEBUG
	printf("encrypt_key = ");
	for(size_t i=0; i<block_size; i++ ) {
		printf("%x", key_ret[i]);
	}

	printf("\n");
	/* debug end */
#endif //ENC_DEBUG

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

	srand((unsigned int) time(NULL));
	for(size_t i=0; i<iv_len; i++) {
		iv_buf[i] = (rand() % 254 ) + 1;
	}

	return iv_buf;
}

// using aes-128-cfb and nopadding
size_t encrypt_data(const unsigned char *src_data, size_t srclen, struct frp_coder *encoder, unsigned char **ret)
{
	uint8_t *intext = src_data;
	assert(intext);
	struct frp_coder *c = encoder;
	int outlen = 0, tmplen = 0;
	uint8_t *outbuf = NULL;
	if (!encoder) {
		debug(LOG_DEBUG, "encoder not initialized");
		c = init_main_encoder();
		assert(c);
		outbuf = calloc(srclen+16, 1);
		assert(outbuf);
		*ret = outbuf;
		memcpy(outbuf, c->iv, 16);
		outlen += 16;
		outbuf += 16;
	} else {
		outbuf = calloc(srclen, 1);
		assert(outbuf);
		*ret = outbuf;
	}

	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, c->key, c->iv);
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
	EVP_CIPHER_CTX_free(ctx);

E_END:
	return outlen;
}

size_t 
decrypt_data(const uint8_t *enc_data, size_t enc_len, struct frp_coder *decoder, uint8_t **ret)
{
	uint8_t *inbuf = enc_data;
	uint8_t *outbuf = calloc(enc_len, 1);
	struct frp_coder *c = decoder;
	assert(inbuf);
	assert(outbuf);
	*ret = outbuf;
	
	assert(decoder);
	
	int outlen = 0, tmplen = 0;
	EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, c->key, c->iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if(!EVP_DecryptUpdate(ctx, outbuf, &tmplen, inbuf, enc_len)) {
		debug(LOG_ERR, "EVP_DecryptUpdate error!");
		goto D_END;
	}
	outlen += tmplen;

	if(!EVP_DecryptFinal_ex(ctx, outbuf+outlen, &tmplen)) {
		debug(LOG_ERR, "EVP_DecryptFinal_ex error");
		goto D_END;
	}
	outlen += tmplen;
	EVP_CIPHER_CTX_free(ctx);

D_END:
	return outlen;
}

static size_t 
deprecated_decrypt_data(const unsigned char *enc_data, size_t enc_len, struct frp_coder *decoder, unsigned char **ret)
{
	uint8_t *inbuf = enc_data;
	uint8_t *outbuf = calloc(enc_len, 1);
	struct frp_coder *c = decoder;
	assert(inbuf);
	assert(outbuf);
	*ret = outbuf;
	
	assert(decoder);
	
	printf("decrypt_data iv is : ");
	for(int i = 0; i < block_size; i++)
		printf("%1x", c->iv[i]);
	printf("\n");
	
	printf("decrypt_data key is : ");
	for(int i = 0; i < block_size; i++)
		printf("%1x", c->key[i]);
	printf("\n");

	int outlen = 0, tmplen = 0;
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, c->key, c->iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	int loop_times = enc_len / 10;
	int latest_len = enc_len % 10;
	int i = 0;
	int totol_len = 0;
	int enc_per_len;
	for(i=0; i<=loop_times; i++) {
		if (i == loop_times) {
			enc_per_len = latest_len;
		} else {
			enc_per_len = 10;
		}

		if(!EVP_DecryptUpdate(ctx, outbuf + (i*10), &outlen, inbuf + (i*10), enc_per_len)) {
			debug(LOG_ERR, "EVP_DecryptUpdate error!");
			goto D_END;
		}
		totol_len += outlen;
	}


	if(!EVP_DecryptFinal_ex(ctx, outbuf+totol_len, &tmplen)) {
		debug(LOG_ERR, "EVP_DecryptFinal_ex error");
		goto D_END;
	}

	totol_len += tmplen;
	EVP_CIPHER_CTX_free(ctx);

D_END:
	return totol_len;
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
