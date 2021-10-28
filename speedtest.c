#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include "randombytes.h"
#if 0
#include "crypto_scalarmult_curve25519.h"
#include "crypto_scalarmult_x448.h"
#include "crypto_scalarmult_nistp256.h"
#endif
#include "tls.h"

unsigned char pk[133];
unsigned char sk[66];

unsigned char key[32];
unsigned char buf[8192];
unsigned char n[12];


void measure_scalarmult(const char *name, int (*base)(unsigned char *, const unsigned char *), int (*scalarmult)(unsigned char *, const unsigned char *, const unsigned char *)) {

    long num = 10;
    for (;;) {
        clock_t begin, end;
        double tt;
        long k;

        begin = clock();
        for (k = num; k > 0; k --) {
            base(pk, sk);
        }
        end = clock();
        tt = (double)(end - begin) / CLOCKS_PER_SEC;
        if (tt >= 2.0) {
            printf("%-30s %8.2f mulgen/s\n", name,
                (double)num / tt);
            fflush(stdout);
            break;
        }
        num <<= 1;
    }

    num = 10;
    for (;;) {
        clock_t begin, end;
        double tt;
        long k;

        begin = clock();
        for (k = num; k > 0; k --) {
            scalarmult(pk, sk, pk);
        }
        end = clock();
        tt = (double)(end - begin) / CLOCKS_PER_SEC;
        if (tt >= 2.0) {
            printf("%-30s %8.2f mul/s\n", name,
                (double)num / tt);
            fflush(stdout);
            break;
        }
        num <<= 1;
    }
}

void measure_symetric(const char *name, uint32_t (*symetric)(const void *kv, const void *nv, uint32_t u, void *mv, size_t l)) {

    long num = 10;
    for (;;) {
        clock_t begin, end;
        double tt;
        long k;

        begin = clock();
        for (k = num; k > 0; k --) {
            symetric(key, n, 0, buf, sizeof buf);
        }
        end = clock();
        tt = (double)(end - begin) / CLOCKS_PER_SEC;
        if (tt >= 2.0) {
            printf("%-30s %8.2f MB/s\n", name,
                ((double)sizeof buf) * (double)num
                / (tt * 1000000.0));
            fflush(stdout);
            break;
        }
        num <<= 1;
    }

}

int main(void) {

    randombytes(sk, sizeof sk);

#if 0
    measure_scalarmult("x25519", crypto_scalarmult_curve25519_base, crypto_scalarmult_curve25519);
    measure_scalarmult("p256", crypto_scalarmult_nistp256_base, crypto_scalarmult_nistp256);
    measure_scalarmult("x448", crypto_scalarmult_x448_base, crypto_scalarmult_x448);
#endif

#if 0
    measure_symetric("chacha20_vec", br_chacha20_vec_run);
#endif
    measure_symetric("chacha20_ct", br_chacha20_ct_run); 

#if __SSE2__
    measure_symetric("chacha20_sse2", br_chacha20_sse2_run); 
#endif
}
