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
#ifdef ENC_DEBUG
	printf("encrypt_key = ");
	int i = 0;
	for(i=0; i<block_size; i++ ) {
		printf("%u ", *(key_ret + i));
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
	size_t i;
	for(i=0; i<iv_len; i++) {
		iv_buf[i] = (rand() % 254 ) + 1;
	}

	return iv_buf;
}

// using aes-128-cfb and nopadding
size_t encrypt_data(const unsigned char *src_data, size_t srclen, struct frp_coder *encoder, unsigned char **ret)
{
	unsigned char *intext = calloc(srclen, 1);	// free in func
	assert(intext);
	memcpy(intext, src_data, srclen);

	unsigned char *outbuf = calloc(srclen, 1);
	assert(outbuf);
	*ret = outbuf;

	int outlen = 0, tmplen = 0;
	struct frp_coder *c = encoder;
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_aes_128_cfb(), NULL, c->key, c->iv);
	if(!EVP_EncryptUpdate(&ctx, outbuf, &outlen, intext, (int)srclen)) {
		debug(LOG_ERR, "EVP_EncryptUpdate error!");
		goto E_END;
	}

	if(!EVP_EncryptFinal_ex(&ctx, outbuf+outlen, &tmplen)) {
		debug(LOG_ERR, "EVP_EncryptFinal_ex error!");
		goto E_END;
	}

	outlen += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);

#ifdef ENC_DEBUG
	int j = 0;
	debug(LOG_DEBUG, "encoder iv=");
	for (j=0; j<16; j++){
		printf("%u ", (unsigned char)c->iv[j]) ;
	}
	printf("\n");

	debug(LOG_DEBUG, "encoder KEY=");
	for (j=0; j<16; j++){
		printf("%u ", (unsigned char)c->key[j]);
	}
	printf("\n");

	debug(LOG_DEBUG, "encoder result 10 =");
	for (j = 0; j<outlen; j++) {
		printf("%d ", (unsigned char)outbuf[j]);
	}
	printf("\n");
#endif //ENC_DEBUG

E_END:
	free(intext);
	return outlen;
}

size_t decrypt_data(const unsigned char *enc_data, size_t enc_len, struct frp_coder *decoder, unsigned char **ret)
{
	unsigned char *inbuf = malloc(enc_len);
	assert(inbuf);
	memcpy(inbuf, enc_data, enc_len);

	unsigned char *outbuf = malloc(enc_len);
	assert(outbuf);
	*ret = outbuf;

	int outlen = 0, tmplen = 0;
	struct frp_coder *c = decoder;
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_aes_128_cfb(), NULL, c->key, c->iv);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

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

		if(!EVP_DecryptUpdate(&ctx, outbuf + (i*10), &outlen, inbuf + (i*10), enc_per_len)) {
			debug(LOG_ERR, "EVP_DecryptUpdate error!");
			goto D_END;
		}
		totol_len += outlen;
	}


	if(!EVP_DecryptFinal_ex(&ctx, outbuf+totol_len, &tmplen)) {
		debug(LOG_ERR, "EVP_DecryptFinal_ex error");
		goto D_END;
	}

	totol_len += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);

#ifdef ENC_DEBUG
	debug(LOG_DEBUG, "DEC_LEN:%lu", enc_len);
	int j = 0;
	debug(LOG_DEBUG, "decoder IV=");
	for (j=0; j<16; j++){
		printf("%u ", (unsigned char)c->iv[j] );
	}
	printf("\n");

	debug(LOG_DEBUG, "decoder KEY=");
	for (j=0; j<16; j++){
		printf("%u ", (unsigned char)c->key[j] );
	}
	printf("\n");

	debug(LOG_DEBUG, "decoder source=");
	for (j=0; j<enc_len; j++){
		printf("%u ", (unsigned char)inbuf[j]);
	}
	printf("\n");

	debug(LOG_DEBUG, "decoder result=");
	for (j = 0; j<totol_len; j++) {
		printf("%u ", (unsigned char)(*ret)[j]);
	}
	printf("\n");

	debug(LOG_DEBUG, "decode string=%s", outbuf);
#endif //ENC_DEBUG

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
