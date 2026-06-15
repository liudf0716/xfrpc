// SPDX-License-Identifier: GPL-3.0-only
/*
 * SSL/TLS compatibility header.
 *
 * Always includes real OpenSSL headers for crypto (EVP, RAND, MD5) and
 * TLS (SSL) APIs.  wolfSSL's OpenSSL-compat layer is incomplete — it
 * lacks EVP_aes_128_cfb128 and other ciphers required by frp's protocol.
 *
 * libevent's bufferevent_openssl_socket_new also requires real OpenSSL's
 * struct ssl_st, so tls.c uses real OpenSSL directly.
 *
 * Files that need only wolfSSL for a specific purpose should include
 * wolfssl/options.h and wolfssl/openssl/ssl.h directly.
 */

#ifndef XFRPC_SSL_COMPAT_H
#define XFRPC_SSL_COMPAT_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/md5.h>

#endif /* XFRPC_SSL_COMPAT_H */
