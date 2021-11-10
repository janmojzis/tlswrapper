#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>
#include "log.h"
#include "bearssl.h"
#include "randombytes.h"

static br_chacha20_run chacha_run = 0;
static int initialized = 0;

static void _init(void) {

    chacha_run = br_chacha20_sse2_get();
    if (chacha_run) {
        log_d1("randombytes use chacha20 SSE2");
        return;
    }

    chacha_run = &br_chacha20_ct_run;
    log_d1("randombytes use chacha20 CT");
}

static void _key(unsigned char k[32]) {

    for (;;) {
        if (getentropy(k, 32) == 0) break;
        log_w1("getentropy failed, waiting one second");
        sleep(1);
    }
}

static void _nonce(unsigned char n[12]) {

    struct timespec t;
    long long i;

    clock_gettime(CLOCK_REALTIME, &t);
    for (i = 0; i < 6; ++i) { n[i + 0] = t.tv_sec;  t.tv_sec >>= 8;  }
    for (i = 0; i < 6; ++i) { n[i + 6] = t.tv_nsec; t.tv_nsec >>= 8; }
}

void randombytes(void *xv, unsigned long long xlen) {

    unsigned char *x = (unsigned char *)xv;
    unsigned long long i;
    unsigned char k[32], n[12];

    if (!initialized) {
        _init();
        initialized = 1;
    }

    while (xlen > 0) {
        if (xlen < 1073741824)
            i = xlen;
        else
            i = 1073741824;

        _key(k);
        _nonce(n);
        memset(x, 0, i);
        (void) chacha_run(k, n, 0, x, i);
        x += i;
        xlen -= i;
    }
    __asm__ __volatile__("" : : "r"(xv) : "memory");
}
