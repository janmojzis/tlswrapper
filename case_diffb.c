#include "case.h"

long long case_diffb(const char *yv, long long ylen, const char *xv) {

    unsigned char a, b;
    const unsigned char *y = (unsigned char *) yv;
    const unsigned char *x = (unsigned char *) xv;

    while (ylen > 0) {
        a = *x++ - 'A';
        b = *y++ - 'A';
        --ylen;
        if (a <= 'Z' - 'A')
            a += 'a';
        else
            a += 'A';
        if (b <= 'Z' - 'A')
            b += 'a';
        else
            b += 'A';
        if (a != b) return ((int) (unsigned int) b) - ((int) (unsigned int) a);
    }
    return 0;
}
