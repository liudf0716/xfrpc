#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "fastpbkdf2.h"

static void write32_be(uint32_t n, uint8_t out[4]) {
    out[0] = (n >> 24) & 0xff;
    out[1] = (n >> 16) & 0xff;
    out[2] = (n >> 8) & 0xff;
    out[3] = n & 0xff;
}

static void xor_block(uint8_t *out, const uint8_t *in) {
    size_t i;
    for (i = 0; i < EVP_MAX_MD_SIZE; i++) {
        out[i] ^= in[i];
    }
}

static void pbkdf2_impl(const EVP_MD *md,
                       const uint8_t *pw, size_t npw,
                       const uint8_t *salt, size_t nsalt,
                       uint32_t iterations,
                       uint8_t *out, size_t nout) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[2];
    uint32_t counter = 1;
    unsigned int digestlen;
    size_t remain = nout;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                               (char *)EVP_MD_name(md), 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(ctx, pw, npw, params);

    while (remain > 0) {
        uint8_t countbuf[4];
        uint8_t Txi[EVP_MAX_MD_SIZE];
        uint8_t Ti[EVP_MAX_MD_SIZE];
        size_t copy;
        size_t outlen;

        write32_be(counter, countbuf);

        /* First iteration */
        EVP_MAC_init(ctx, NULL, 0, NULL);
        EVP_MAC_update(ctx, salt, nsalt);
        EVP_MAC_update(ctx, countbuf, 4);
        EVP_MAC_final(ctx, Ti, &outlen, EVP_MAX_MD_SIZE);
        digestlen = outlen;
        memcpy(Txi, Ti, digestlen);

        /* Subsequent iterations */
        for (uint32_t i = 1; i < iterations; i++) {
            EVP_MAC_init(ctx, NULL, 0, NULL);
            EVP_MAC_update(ctx, Ti, digestlen);
            EVP_MAC_final(ctx, Ti, &outlen, EVP_MAX_MD_SIZE);
            xor_block(Txi, Ti);
        }

        copy = (remain > digestlen) ? digestlen : remain;
        memcpy(out, Txi, copy);
        out += copy;
        remain -= copy;
        counter++;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

void fastpbkdf2_hmac_sha1(const uint8_t *pw, size_t npw,
                         const uint8_t *salt, size_t nsalt,
                         uint32_t iterations,
                         uint8_t *out, size_t nout) {
    pbkdf2_impl(EVP_sha1(), pw, npw, salt, nsalt, iterations, out, nout);
}

void fastpbkdf2_hmac_sha256(const uint8_t *pw, size_t npw,
                           const uint8_t *salt, size_t nsalt,
                           uint32_t iterations,
                           uint8_t *out, size_t nout) {
    pbkdf2_impl(EVP_sha256(), pw, npw, salt, nsalt, iterations, out, nout);
}

void fastpbkdf2_hmac_sha512(const uint8_t *pw, size_t npw,
                           const uint8_t *salt, size_t nsalt,
                           uint32_t iterations,
                           uint8_t *out, size_t nout) {
    pbkdf2_impl(EVP_sha512(), pw, npw, salt, nsalt, iterations, out, nout);
}