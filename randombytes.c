#include <unistd.h>
#include <time.h>
#include <sys/random.h>
#include "log.h"
#include "bearssl.h"
#include "randombytes.h"

void randombytes(void *x, unsigned long long xlen) {

    unsigned char k[32], n[12];
    struct timespec t;
    long long i;

    /* key */
    for (;;) {
        if (getentropy(k, sizeof k) == 0) break;
        log_w1("getentropy failed, waiting one second");
        sleep(1);
    }

    /* nonce */
    clock_gettime(CLOCK_REALTIME, &t);
    for (i = 0; i < 6; ++i) { n[i + 0] = t.tv_sec;  t.tv_sec >>= 8;  }
    for (i = 0; i < 6; ++i) { n[i + 6] = t.tv_nsec; t.tv_nsec >>= 8; }

    (void) br_chacha20_ct_run(k, n, 0, x, xlen);
    __asm__ __volatile__("" : : "r"(x) : "memory");
}
