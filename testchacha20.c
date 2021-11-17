#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include "log.h"
#include "bearssl.h"

unsigned char k[32];
unsigned char n[12];
unsigned char buf[1024];
static br_chacha20_run chacha = 0;

void measure_symetric(const char *name, uint32_t (*symetric)(const void *kv, const void *nv, uint32_t u, void *mv, size_t l)) {

    long long i, num = 10;
    clock_t begin, end;
    double tt;

    for (;;) {

        begin = clock();
        for (i = num; i > 0; --i) {
            symetric(k, n, 0, buf, sizeof buf);
        }
        end = clock();
        tt = (double)(end - begin) / CLOCKS_PER_SEC;
        if (tt >= 2.0) {
            num = (long long)(((double) sizeof buf) * (double)num / (tt * 1000000.0));
            log_i4(name, ": ", lognum(num), " MB/s");
            break;
        }
        num <<= 1;
    }
}

int main() {

    log_level(4);
    log_name("testchacha20");

    chacha = br_chacha20_sse2_get();
    if (chacha) {
        measure_symetric("chacha20_sse2", chacha);
    }
    measure_symetric("chacha20_ct", br_chacha20_ct_run);

    _exit(0);

}
