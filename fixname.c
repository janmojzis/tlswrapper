#include "fixname.h"

void fixname(char *x, long long xlen) {

    long long i;

    for (i = 0; i < xlen; ++i) {
        if (x[i] == '@') x[i] = 0;
    }
}
