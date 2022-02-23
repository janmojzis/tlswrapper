/*
version 20220222
*/

#include <unistd.h>
#ifdef __APPLE__
#include <sys/random.h>
#endif
#include "randombytes.h"

void randombytes(void *xv, long long xlen) {

    long long i;
    unsigned char *x = (unsigned char *) xv;

    while (xlen > 0) {
        if (xlen < 256)
            i = xlen;
        else
            i = 256;

        if (getentropy(x, i) == -1) {
            sleep(1);
            continue;
        }
        x += i;
        xlen -= i;
    }
    __asm__ __volatile__("" : : "r"(xv) : "memory");
}
