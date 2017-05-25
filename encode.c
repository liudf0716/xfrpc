#include <string.h>
#include <stdio.h>

#include "fastpbkdf2.h"

static const char *salt = "frp";

char *encrypt_key(char *token, size_t token_len) 
{
	char out[17] = {0};
	fastpbkdf2_hmac_sha1(token, token_len, salt, strlen(salt), 64, *out, 16);

	printf("KEY = %s\n", out);

}