
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "fastpbkdf2.h"

void fastpbkdf2_hmac_sha1(const uint8_t *pw, size_t npw,
                         const uint8_t *salt, size_t nsalt,
                         uint32_t iterations,
                         uint8_t *out, size_t nout) {
    PKCS5_PBKDF2_HMAC((const char *)pw, npw,
                      salt, nsalt, iterations,
                      EVP_sha1(), nout, out);
}

void fastpbkdf2_hmac_sha256(const uint8_t *pw, size_t npw,
                           const uint8_t *salt, size_t nsalt,
                           uint32_t iterations,
                           uint8_t *out, size_t nout) {
    PKCS5_PBKDF2_HMAC((const char *)pw, npw,
                      salt, nsalt, iterations,
                      EVP_sha256(), nout, out);
}

void fastpbkdf2_hmac_sha512(const uint8_t *pw, size_t npw,
                           const uint8_t *salt, size_t nsalt,
                           uint32_t iterations,
                           uint8_t *out, size_t nout) {
    PKCS5_PBKDF2_HMAC((const char *)pw, npw,
                        salt, nsalt, iterations,
                        EVP_sha512(), nout, out);
}