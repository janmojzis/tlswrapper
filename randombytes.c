#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "bearssl.h"
#include "log.h"
#include "randombytes.h"

static int fd = -1;

static void _urandombytes(void *xv, unsigned long long xlen) {

    long long i;
    unsigned char *x = xv;

    if (fd == -1) {
        for (;;) {
#ifdef O_CLOEXEC
            fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
#else
            fd = open("/dev/urandom", O_RDONLY);
            fcntl(fd, F_SETFD, 1);
#endif
            if (fd != -1) break;
            log_w1("_urandombytes unable to open /dev/urandom, sleeping one second");
            sleep(1);
        }
    }

    while (xlen > 0) {
        if (xlen < 1048576) i = xlen; else i = 1048576;

        i = read(fd, x, i);
        if (i < 1) {
            log_w1("_urandombytes unable to read from /dev/urandom, sleeping one second");
            sleep(1);
            continue;
        }

        x += i;
        xlen -= i;
    }
}

static br_chacha20_run chacha_run = 0;
static int initialized = 0;

static void _randombytes_init(void) {

    chacha_run = br_chacha20_sse2_get();
    if (chacha_run) {
        log_t1("_randombytes_init() = chacha20 SSE2");
        return;
    }

    chacha_run = &br_chacha20_ct_run;
    log_t1("_randombytes_init() = chacha20 CT");
}

void randombytes(void *xv, unsigned long long xlen) {

    unsigned char *x = (unsigned char *)xv;
    unsigned long long i;
    unsigned char k[32 + 12];

    if (!initialized) {
        _randombytes_init();
        initialized = 1;
    }

    while (xlen > 0) {
        if (xlen < 1073741824) i = xlen; else i = 1073741824;

        _urandombytes(k, sizeof k);
        memset(x, 0, i);
        (void) chacha_run(k, k + 32, 0, x, i);
        x += i;
        xlen -= i;
    }

    __asm__ __volatile__("" : : "r"(xv) : "memory");
}
