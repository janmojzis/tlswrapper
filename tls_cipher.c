#include <string.h>
#include "tls.h"

const tls_cipher tls_ciphers[] = {
    {
        "CHACHA20_POLY1305_SHA256",
        tls_cipher_CHACHA20_POLY1305_SHA256,
        "ECDSA + ECDHE + ChaCha20+Poly1305 encryption (TLS 1.2+)",
        "RSA + ECDHE + ChaCha20+Poly1305 encryption (TLS 1.2+)",
    },
    {
        "AES_256_GCM_SHA384",
        tls_cipher_AES_256_GCM_SHA384,
        "ECDSA + ECDHE + AES-256/GCM encryption (TLS 1.2+)",
        "RSA + ECDHE + AES-256/GCM encryption (TLS 1.2+)",
    },
    {
        "AES_128_GCM_SHA256",
        tls_cipher_AES_128_GCM_SHA256,
        "ECDSA + ECDHE + AES-128/GCM encryption (TLS 1.2+)",
        "RSA + ECDHE + AES-128/GCM encryption (TLS 1.2+)",
    },
    {
        "AES_256_CBC_SHA384",
        tls_cipher_AES_256_CBC_SHA384,
        "ECDSA + ECDHE + AES-256/CBC + SHA-384 (TLS 1.2+)",
        "RSA + ECDHE + AES-256/CBC + SHA-384 (TLS 1.2+)",
    },
    {
        "AES_128_CBC_SHA256",
        tls_cipher_AES_128_CBC_SHA256,
        "ECDSA + ECDHE + AES-128/CBC + SHA-256 (TLS 1.2+)",
        "RSA + ECDHE + AES-128/CBC + SHA-256 (TLS 1.2+)",
    },
    {
        "AES_256_CBC_SHA",
        tls_cipher_AES_256_CBC_SHA,
        "ECDSA + ECDHE + AES-256/CBC + SHA-1",
        "RSA + ECDHE + AES-256/CBC + SHA-1",
    },
    {
        "AES_128_CBC_SHA",
        tls_cipher_AES_128_CBC_SHA,
        "ECDSA + ECDHE + AES-128/CBC + SHA-1",
        "RSA + ECDHE + AES-128/CBC + SHA-1",
    },
    { 0, 0, 0, 0 }
};


const char *tls_cipher_str(uint16_t suite) {

    long long i;

    for (i = 0; tls_ciphers[i].name; ++i) {
        if (((tls_ciphers[i].suite >> 16) & 0xffff) == suite) return tls_ciphers[i].eccomment;
        if (((tls_ciphers[i].suite >>  0) & 0xffff) == suite) return tls_ciphers[i].rsacomment;
    }
    return "unknown cipher";
}

static int use_default = 1;
int tls_cipher_add(struct tls_context *ctx, const char *x) {

    size_t i;
    uint32_t suite = 0;

    if (use_default == 1) {
        ctx->cipher_enabled_len = 0;
        use_default = 0;
    }

    for (i = 0; tls_ciphers[i].name; ++i) {
        if (strcmp(x, tls_ciphers[i].name)) continue;
        suite = tls_ciphers[i].suite;
        goto ok;
    }

    return 0;

ok:

    if (suite) {
        for (i = 0; i < ctx->cipher_enabled_len; ++i) {
            if (ctx->cipher_enabled[i] == (suite & 0xffff)) {
                suite = 0;
                break;
            }
        }
    }

    if (suite) {
        ctx->cipher_enabled[ctx->cipher_enabled_len++] = (suite >> 16) & 0xffff;
        ctx->cipher_enabled[ctx->cipher_enabled_len++] = (suite >>  0) & 0xffff;
    }

    return 1;
}

uint32_t tls_cipher_get(uint16_t suite) {

    long long i;

    for (i = 0; tls_ciphers[i].name; ++i) {
        if (((tls_ciphers[i].suite >> 16) & 0xffff) == suite) return tls_ciphers[i].suite;
        if (((tls_ciphers[i].suite >>  0) & 0xffff) == suite) return tls_ciphers[i].suite;
    }
    return 0;
}
