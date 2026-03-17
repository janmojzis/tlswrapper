/*
 * haslib25519.c - verify the external lib25519 feature set
 *
 * This probe is compiled during feature detection to confirm that the
 * linked lib25519 API provides the expected DH and signature behavior.
 */

#include <lib25519.h>

#if lib25519_nP_montgomery25519_SCALARBYTES != lib25519_dh_SECRETKEYBYTES
#error
#endif
#if lib25519_nP_montgomery25519_POINTBYTES != lib25519_dh_PUBLICKEYBYTES
#error
#endif
#if lib25519_nP_montgomery25519_POINTBYTES != lib25519_dh_BYTES
#error
#endif
#if lib25519_nG_montgomery25519_SCALARBYTES != lib25519_dh_SECRETKEYBYTES
#error
#endif
#if lib25519_nG_montgomery25519_POINTBYTES != lib25519_dh_PUBLICKEYBYTES
#error
#endif
#if lib25519_nG_montgomery25519_POINTBYTES != lib25519_dh_BYTES
#error
#endif

static unsigned char k[lib25519_dh_BYTES];
static unsigned char k2[lib25519_dh_BYTES];
static unsigned char pk[lib25519_dh_PUBLICKEYBYTES];
static unsigned char pk2[lib25519_dh_PUBLICKEYBYTES];
static unsigned char sk[lib25519_dh_SECRETKEYBYTES];
static unsigned char signsk[lib25519_sign_SECRETKEYBYTES];
static unsigned char signpk[lib25519_sign_PUBLICKEYBYTES];
static unsigned char signs[lib25519_sign_BYTES + /*m*/ lib25519_dh_BYTES];
static long long signslen;
static long long klen;

/*
 * z - map any non-zero byte to zero
 *
 * @x: byte to normalize
 *
 * Returns 0 for every possible input value. The probe uses this helper
 * to fold arbitrary output bytes into a single success accumulator.
 */
static unsigned char z(unsigned char x) {

    unsigned long long z = (unsigned long long) x + 1ULL;
    unsigned long long t = z;
    long long i;

    for (i = 6; i >= 0; --i) {
        t = (t * t) % 257;
        t = (t * z) % 257;
    }
    t = (t * z) % 257;
    return t - 1;
}

/*
 * main - probe whether the external lib25519 API matches expectations
 *
 * @argc: unused
 * @argv: unused
 *
 * Exercises the DH and signature entry points and returns 0 when the
 * linked implementation behaves as expected for build-time detection.
 */
int main(int argc, char **argv) {
    unsigned char ret = 0;
    long long i;

    (void) argc;
    (void) argv;

    lib25519_dh_keypair(pk, sk);
    lib25519_nG_montgomery25519(pk2, sk);
    for (i = 0; i < lib25519_dh_PUBLICKEYBYTES; ++i) ret |= pk[i] ^ pk2[i];

    lib25519_dh(k, pk, sk);
    lib25519_nP_montgomery25519(k2, sk, pk);
    for (i = 0; i < lib25519_dh_BYTES; ++i) ret |= k[i] ^ k2[i];

    lib25519_sign_keypair(signpk, signsk);
    lib25519_sign(signs, &signslen, k, sizeof k, signsk);
    if (signslen != sizeof signs) ret |= 1;

    ret |= lib25519_sign_open(k2, &klen, signs, signslen, signpk);
    if (klen != sizeof k2) ret |= 1;
    for (i = 0; i < lib25519_dh_BYTES; ++i) ret |= k[i] ^ k2[i];

    for (i = 0; i < sizeof signs; ++i) ret |= z(signs[i]);
    return ret;
}
