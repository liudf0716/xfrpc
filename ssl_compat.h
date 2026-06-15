// SPDX-License-Identifier: GPL-3.0-only
/*
 * SSL/TLS compatibility header.
 *
 * When USE_WOLFSSL is defined (via CMake), crypto functions use wolfSSL's
 * OpenSSL-compat headers.  tls.c keeps using real OpenSSL for libevent
 * bufferevent_ssl compatibility (bufferevent_openssl_socket_new expects
 * struct ssl_st *).
 */

#ifndef XFRPC_SSL_COMPAT_H
#define XFRPC_SSL_COMPAT_H

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/rand.h>
#include <wolfssl/openssl/md5.h>
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#endif

#endif /* XFRPC_SSL_COMPAT_H */
