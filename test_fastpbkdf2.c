#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

void pbkdf2_key(const uint8_t *password, size_t password_len,
                const uint8_t *salt, size_t salt_len,
                uint32_t iterations, uint8_t *out, size_t out_len) {
    PKCS5_PBKDF2_HMAC((const char *)password, password_len,
                      salt, salt_len, iterations,
                      EVP_sha1(), out_len, out);
}

int main() {
    const char *password = "password";
    const uint8_t salt[] = "saltsalt";
    uint8_t key[16]; // size of the derived key

    pbkdf2_key((const uint8_t *)password, strlen(password),
               salt, sizeof(salt) - 1, 1000, key, sizeof(key));

    printf("Derived key: ");
    for (size_t i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}