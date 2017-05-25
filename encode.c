#include <string.h>
#include <stdio.h>

#include "fastpbkdf2.h"
#include "encode.h"
#include "config.h"

static const char *salt = "frp";

// 29 201 136 254 206 150 233 65 13 82 120 149 203 228 122 128 
char *encrypt_key(char *token, size_t token_len) 
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

	
}

char *encrypt_data(char *src_data, size_t srlen)
{
	struct common_conf *c_conf = get_common_config();
	encrypt_key(c_conf->privilege_token, strlen(c_conf->privilege_token));
}