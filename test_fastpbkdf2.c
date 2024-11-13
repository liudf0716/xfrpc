#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fastpbkdf2.h"

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_fastpbkdf2_hmac_sha1() {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    uint32_t iterations = 1000;
    uint8_t output[20]; // SHA-1 produces a 20-byte hash

    fastpbkdf2_hmac_sha1(password, strlen((const char *)password), salt, strlen((const char *)salt), iterations, output, sizeof(output));

    printf("PBKDF2-HMAC-SHA1: ");
    print_hex(output, sizeof(output));
}

int main() {
    test_fastpbkdf2_hmac_sha1();
    return 0;
}