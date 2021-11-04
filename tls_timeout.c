#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "tls.h"

int tls_timeout_parse(long long *num, const char *x) {

    char *endptr = 0;

    *num = strtoll(x, &endptr, 10);

    if (!x || strlen(x) == 0 || !endptr || endptr[0]) {
        log_f2("unable to parse timeout from the string ", x);
        return 0;
    }
    if (*num < 1) {
        log_f2("timeout must be a number > 0, not ", x);
        return 0;
    }
    return 1;
}
