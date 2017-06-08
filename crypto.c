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
#include "debug.h"

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
		// key_ret[i] = (unsigned char)"b";
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
		iv_buf[i] = 9;
		printf("iv[%ld]=%d ", i, iv_buf[i]);
	}

	printf("\n");
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

#define ENC_DBG 1
#ifdef ENC_DBG
	int j = 0;
	debug(LOG_DEBUG, "encoder iv=");
	for (j=0;j<16;j++){
		printf("%u ", (unsigned char)c->iv[j] ) ;
	}
	printf("\n");

	debug(LOG_DEBUG, "encoder result 10 =");
	for (j = 0; j<outlen; j++) {
		printf("%d ", (unsigned char)outbuf[j]);
	}
	printf("\n");
#endif //ENC_DBG

E_END:
	free(intext);
	return outlen;
}

size_t decrypt_data(const unsigned char *enc_data, size_t enc_len, struct frp_coder *decoder, unsigned char **ret)
{
	unsigned char *inbuf = calloc(enc_len, 1);
	assert(inbuf);
	memcpy(inbuf, enc_data, enc_len);

	// unsigned char inbuf[] = {228, 173, 25, 145, 226, 75, 25, 78, 7, 106};

	unsigned char *outbuf = calloc(enc_len, 1);
	assert(outbuf);
	*ret = outbuf;

	int outlen = 0, tmplen = 0;
	struct frp_coder *c = decoder;
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_aes_128_cfb(), NULL, c->key, c->iv);
	
	if(!EVP_DecryptUpdate(&ctx, outbuf, &outlen, inbuf, (int)enc_len)) {
		debug(LOG_ERR, "EVP_DecryptUpdate error!");
		goto D_END;
	}

	if(!EVP_DecryptFinal_ex(&ctx, outbuf+outlen, &tmplen)) {
		debug(LOG_ERR, "EVP_DecryptFinal_ex error");
		goto D_END;
	}

	outlen += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);

#define DEC_DBG 1
#ifdef DEC_DBG
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
	for (j = 0; j<outlen; j++) {
		printf("%u ", (unsigned char)outbuf[j]);
	}
	printf("\n");

	debug(LOG_DEBUG, "decode string=%s", outbuf);
#endif //DEC_DBG

D_END:
	free(inbuf);
	return outlen;
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
