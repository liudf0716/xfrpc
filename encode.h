#ifndef _ENCODE_H_
#define _ENCODE_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *encrypt_key(char *token, size_t token_len);
char *encrypt_data(char *src_data, size_t srlen);

#endif // _ENCODE_H_