/*
 * tls_cipher.c - define supported TLS cipher suites
 *
 * This module exposes the cipher suite table used for configuration and
 * logging. It maps user-facing names to the BearSSL suite identifiers
 * required for both ECDSA and RSA certificate variants.
 */

#include "str.h"
#include "log.h"
#include "tls.h"

const tls_cipher tls_ciphers[] = {
    {
        "CHACHA20_POLY1305_SHA256",
        BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        "ECDSA + ECDHE + ChaCha20+Poly1305 (TLS 1.2+)",
        "RSA + ECDHE + ChaCha20+Poly1305 (TLS 1.2+)",
    },
    {
        "AES_256_GCM_SHA384",
        BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "ECDSA + ECDHE + AES256/GCM (TLS 1.2+)",
        "RSA + ECDHE + AES256/GCM (TLS 1.2+)",
    },
    {
        "AES_128_GCM_SHA256",
        BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "ECDSA + ECDHE + AES128/GCM (TLS 1.2+)",
        "RSA + ECDHE + AES128/GCM (TLS 1.2+)",
    },
    {
        "AES_256_CBC_SHA384",
        BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        "ECDSA + ECDHE + AES256/CBC + SHA384 (TLS 1.2+)",
        "RSA + ECDHE + AES256/CBC + SHA384 (TLS 1.2+)",
    },
    {
        "AES_128_CBC_SHA256",
        BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        "ECDSA + ECDHE + AES128/CBC + SHA256 (TLS 1.2+)",
        "RSA + ECDHE + AES128/CBC + SHA256 (TLS 1.2+)",
    },
    {
        "AES_256_CBC_SHA",
        BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        "ECDSA + ECDHE + AES256/CBC + SHA1",
        "RSA + ECDHE + AES256/CBC + SHA1",
    },
    {
        "AES_128_CBC_SHA",
        BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        "ECDSA + ECDHE + AES128/CBC + SHA1",
        "RSA + ECDHE + AES128/CBC + SHA1",
    },
    {0, 0, 0, 0, 0}};

/*
 * tls_cipher_str - return a human-readable cipher suite description
 *
 * @s: BearSSL cipher suite identifier
 *
 * Looks up the configured cipher table and returns a static descriptive
 * string for either the ECDSA or RSA suite variant.
 */
const char *tls_cipher_str(uint16_t s) {

    long long i;

    for (i = 0; tls_ciphers[i].name; ++i) {
        if ((tls_ciphers[i].ecsuite) == s) return tls_ciphers[i].eccomment;
        if ((tls_ciphers[i].rsasuite) == s) return tls_ciphers[i].rsacomment;
    }
    return "unknown cipher";
}

static int use_default = 1;

/*
 * tls_cipher_add - enable a cipher suite pair by configuration name
 *
 * @ctx: TLS context to update
 * @x: configured cipher name
 *
 * Resolves the requested cipher name and appends both certificate-type
 * variants to the enabled suite list. The first explicit add clears the
 * default list before appending user-selected suites.
 *
 * Constraints:
 *   - ctx must have space for two more suite identifiers
 */
int tls_cipher_add(struct tls_context *ctx, const char *x) {

    unsigned long long i;
    uint16_t ecsuite = 0;
    uint16_t rsasuite = 0;

    if (use_default == 1) {
        ctx->cipher_enabled_len = 0;
        use_default = 0;
    }

    for (i = 0; tls_ciphers[i].name; ++i) {
        if (str_diff(x, tls_ciphers[i].name)) continue;
        ecsuite = tls_ciphers[i].ecsuite;
        rsasuite = tls_ciphers[i].rsasuite;
        goto ok;
    }

    return 0;

ok:

    if (ecsuite && rsasuite) {
        for (i = 0; i < ctx->cipher_enabled_len; ++i) {
            if (ctx->cipher_enabled[i] == ecsuite ||
                ctx->cipher_enabled[i] == rsasuite) {
                log_w3("unable to add cipher '", x,
                       "': cipher is already added");
                ecsuite = 0;
                rsasuite = 0;
            }
        }
    }

    if (ecsuite && rsasuite) {
        if ((sizeof ctx->cipher_enabled / sizeof ctx->cipher_enabled[0]) <
            ctx->cipher_enabled_len + 2) {
            log_e3("unable to add cipher '", x, "': too many enabled ciphers");
            return 0;
        }
        ctx->cipher_enabled[ctx->cipher_enabled_len++] = ecsuite;
        ctx->cipher_enabled[ctx->cipher_enabled_len++] = rsasuite;
    }

    return 1;
}
