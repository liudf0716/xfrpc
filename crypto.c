#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <syslog.h>
#include <openssl/ssl.h>
#include <mbedtls/aes.h>

#include "fastpbkdf2.h"
#include "crypto.h"
#include "config.h"
#include "common.h"
#include "debug.h"

static const char *default_salt = "frp";
static const size_t block_size = 16;
static struct frp_coder *main_encoder = NULL;
static struct frp_coder *main_decoder = NULL;

size_t 
get_block_size()
{
	return block_size;
}

struct frp_coder *
new_coder(const char *privilege_token, const char *salt)
{
	struct frp_coder *enc = calloc(sizeof(struct frp_coder), 1);
	assert(enc);

	enc->privilege_token = privilege_token ? strdup(privilege_token):"\0";
	enc->salt = strdup(salt);
	encrypt_key(enc->privilege_token, strlen(enc->privilege_token), enc->salt, enc->key, block_size);
	encrypt_iv(enc->iv, block_size);
	return enc;
}

struct frp_coder *
clone_coder(const struct frp_coder *coder)
{
	assert(coder);
	struct frp_coder *enc = calloc(sizeof(struct frp_coder), 1);
	memcpy(enc, coder, sizeof(*coder));
	enc->privilege_token = strdup(coder->privilege_token);
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
init_main_decoder(unsigned char *iv)
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

static void
print_hex(uint8_t *val, size_t len)
{
	for(int i = 0; i < len; i++)
		printf("%1x", val[i]);
	printf("\n");
}

#define _USE_OPENSSL_

// using aes-128-cfb and nopadding
size_t 
encrypt_data(const unsigned char *src_data, size_t srclen, struct frp_coder *encoder, unsigned char **ret)
{
#ifdef _USE_OPENSSL_
	uint8_t *intext = src_data;
	assert(intext);
	assert(encoder);
	struct frp_coder *c = encoder;
	int outlen = 0, tmplen = 0;
	uint8_t *outbuf = NULL;
	if (!encoder) {
		debug(LOG_DEBUG, "encoder not initialized");
		c = init_main_encoder();
		assert(c);
	}
	outbuf = calloc(srclen, 1);
	assert(outbuf);
	*ret = outbuf;

	static EVP_CIPHER_CTX *ctx = NULL;
	if (!ctx) {
		ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, c->key, c->iv);
	}

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
#else
	assert(encoder);
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, encoder->key, 128);

	size_t iv_off = 0;
	uint8_t *output = calloc(srclen, 1);
	assert(output);
	uint8_t iv[16] = {0};
	memcpy(iv, encoder->iv, 16);
	int nret = mbedtls_aes_crypt_cfb128(&ctx, MBEDTLS_AES_ENCRYPT, srclen, &iv_off, encoder->iv, src_data, output);
	if (nret) {
		free(output);
		debug(LOG_ERR, "EVP_EncryptUpdate error!");
		return nret;
	}
	*ret = output;
	return srclen;
#endif
}

size_t 
decrypt_data(const uint8_t *enc_data, size_t enclen, struct frp_coder *decoder, uint8_t **ret)
{
#ifdef	_USE_OPENSSL_
	uint8_t *inbuf = enc_data;
	uint8_t *outbuf = calloc(enclen, 1);
	struct frp_coder *c = decoder;
	assert(inbuf);
	assert(outbuf);
	*ret = outbuf;
	
	assert(decoder);
	
	int outlen = 0, tmplen = 0;
	static EVP_CIPHER_CTX *ctx= NULL;
	if (!ctx) {
		ctx= EVP_CIPHER_CTX_new();
		EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, c->key, c->iv);
	}

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
#else
	assert(decoder);
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, decoder->key, 128);

	size_t iv_off = 0;
	uint8_t *output = calloc(enclen, 1);
	uint8_t iv[16] = {0};
	memcpy(iv, decoder->iv, 16);
	assert(output);
	int nret = mbedtls_aes_crypt_cfb128(&ctx, MBEDTLS_AES_DECRYPT, enclen, &iv_off, decoder->iv, enc_data, output);
	if (nret) {
		free(output);
		debug(LOG_ERR, "EVP_EncryptUpdate error!");
		return nret;
	}
	*ret = output;
	return enclen;
#endif
}

void 
free_encoder(struct frp_coder *encoder) {
	if (encoder) {
		SAFE_FREE(encoder->privilege_token);
		SAFE_FREE(encoder->salt);
		free(encoder);
	}
}
