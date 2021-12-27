#include <string.h>
#include "buf.h"
#include "iptostr.h"

long long buf_put(void *bufv, long long buflen, long long pos, const void *xv,
                  long long xlen) {

    char *buf = (char *) bufv;
    const char *x = (char *) xv;

    if (!buf) return 0;
    if (buflen < 0) return 0;
    if (!xv) return 0;
    if (xlen < 0) return 0;
    if (pos < 0) return 0;
    if (pos + xlen >= buflen) return 0;

    memcpy(buf + pos, x, xlen);
    return pos + xlen;
}

long long buf_puts(void *buf, long long buflen, long long pos, const void *x) {
    return buf_put(buf, buflen, pos, x, strlen(x));
}
