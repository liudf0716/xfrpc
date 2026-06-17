// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * OIDC authentication for xfrpc.
 * Implements OAuth2 client_credentials grant to obtain access tokens
 * from an OIDC provider's token endpoint.
 *
 * Compatible with frp's auth.oidc.* configuration.
 */

#ifndef XFRPC_OIDC_AUTH_H
#define XFRPC_OIDC_AUTH_H

/**
 * @brief Fetch an OIDC access token using client_credentials grant
 *
 * Makes an HTTP POST to the token endpoint with:
 *   grant_type=client_credentials
 *   client_id=...
 *   client_secret=...
 *   audience=... (optional)
 *   scope=... (optional)
 *
 * @param token_endpoint_url The OIDC token endpoint URL
 * @param client_id          OAuth2 client ID
 * @param client_secret      OAuth2 client secret
 * @param audience           OAuth2 audience (optional, may be NULL)
 * @param scope              OAuth2 scope (optional, may be NULL)
 * @param trusted_ca_file    CA cert for TLS verification (optional)
 * @param insecure_skip_verify Skip TLS verification if 1
 * @return Newly allocated access token string (caller must free), or NULL on error
 */
char *oidc_fetch_token(const char *token_endpoint_url,
                       const char *client_id,
                       const char *client_secret,
                       const char *audience,
                       const char *scope,
                       const char *trusted_ca_file,
                       int insecure_skip_verify);

#endif /* XFRPC_OIDC_AUTH_H */
