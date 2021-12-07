#include "fixname.h"

void fixname(char *x) {

    long long i;

    for (i = 0; x[i]; ++i) {
        if (x[i] == '@') {
            x[i] = 0;
            break;
        }
    }
}
