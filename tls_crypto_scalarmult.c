#include "tls.h"
#include "crypto_scalarmult_curve25519.h"
#ifdef X448
#include "crypto_scalarmult_x448.h"
#endif

int tls_crypto_scalarmult_base(int curve, unsigned char *p, size_t *plen, unsigned char *sk) {

    int ret = -1;
    *plen = 0;

    switch (curve) {
#ifdef X448
        case tls_ecdhe_X448:
            if (crypto_scalarmult_x448_base(p, sk) == 0) ret = 0;
            *plen = 56;
            break;
#endif
        case tls_ecdhe_X25519:
            if (crypto_scalarmult_curve25519_base(p, sk) == 0) ret = 0;
            *plen = 32;
            break;
        case tls_ecdhe_SECP256R1:
            sk[0] &= 127; sk[0] |= 64;
            *plen = br_ec_get_default()->mulgen(p, sk, 32, curve);
            if (*plen == 65) ret = 0;
            break;
        case tls_ecdhe_SECP384R1:
            sk[0] &= 127; sk[0] |= 64;
            *plen = br_ec_get_default()->mulgen(p, sk, 48, curve);
            if (*plen == 97) ret = 0;
            break;
        case tls_ecdhe_SECP521R1:
            sk[0] = 0; sk[1] |= 128;
            *plen = br_ec_get_default()->mulgen(p, sk, 66, curve);
            if (*plen == 133) ret = 0;
            break;
    }
    return ret;
}

int tls_crypto_scalarmult(int curve, unsigned char *p, size_t *plen, unsigned char *sk) {

    unsigned long long i;
    int ret = -1;
    *plen = 0;

    switch (curve) {
#ifdef X448
        case tls_ecdhe_X448:
            if (crypto_scalarmult_x448(p, sk, p) == 0) ret = 0;
            *plen = 56;
            break;
#endif
        case tls_ecdhe_X25519:
            if (crypto_scalarmult_curve25519(p, sk, p) == 0) ret = 0;
            *plen = 32;
            break;
        case tls_ecdhe_SECP256R1:
            sk[0] &= 127; sk[0] |= 64;
            if (br_ec_get_default()->mul(p, 65, sk, 32, curve)) ret = 0;
            for (i = 0; i < 32; ++i) p[i] = p[i + 1];
            *plen = 32;
            break;
        case tls_ecdhe_SECP384R1:
            sk[0] &= 127; sk[0] |= 64;
            if (br_ec_get_default()->mul(p, 97, sk, 48, curve)) ret = 0;
            for (i = 0; i < 48; ++i) p[i] = p[i + 1];
            *plen = 48;
            break;
        case tls_ecdhe_SECP521R1:
            sk[0] = 0; sk[1] |= 128;
            if (br_ec_get_default()->mul(p, 133, sk, 66, curve)) ret = 0;
            for (i = 0; i < 66; ++i) p[i] = p[i + 1];
            *plen = 66;
            break;
    }
    return ret;
}
