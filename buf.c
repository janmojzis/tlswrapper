#include <string.h>
#include "buf.h"

long long buf_put(char *buf, long long buflen, long long pos, const unsigned char *x, long long xlen) {

    if (!buf) return 0;
    if (buflen < 0) return 0;
    if (!x) return 0;
    if (xlen < 0) return 0;
    if (pos < 0) return 0;
    if (pos + xlen >= buflen) return 0;

    memcpy(buf + pos, x, xlen);
    return pos + xlen;
}

long long buf_puts(char *buf, long long buflen, long long pos, const char *x) {
    return buf_put(buf, buflen, pos, (unsigned char *)x, strlen(x));
}
