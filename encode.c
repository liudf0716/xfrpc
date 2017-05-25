#include <string.h>
#include <stdio.h>

#include "fastpbkdf2.h"
#include "encode.h"

static const char *salt = "frp";

char *encrypt_key(char *token, size_t token_len) 
{
	char out[17] = {0};

	fastpbkdf2_hmac_sha1((void *)token, 
						token_len, (void *)salt, 
						strlen(salt), 
						64, 
						(void *)out, 
						16);

	printf("KEY = %s\n", out);
}