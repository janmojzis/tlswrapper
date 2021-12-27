#include <stdlib.h>
#include <string.h>
#include "tls.h"

int tls_timeout_parse(long long *num, const char *x) {

    char *endptr = 0;

    if (!x) return 0;
    if (!strlen(x)) return 0;

    *num = strtoll(x, &endptr, 10);

    if (!endptr) return 0;
    if (endptr[0]) return 0;
    return 1;
}
