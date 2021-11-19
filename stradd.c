#include <string.h>
#include "stradd.h"

size_t stradd(char *buf, size_t buflen, size_t pos, char *x) {

    size_t i, len = strlen(x);

    if (!x) return 0;
    if (pos + len + 2 >= buflen) return 0;

    for (i = 0; i < len; ++i) {
        if (x[i] < 32 || x[i] > 126)
            buf[pos + i] = '?';
        else
            buf[pos + i] = x[i];
    }

    buf[pos + len + 0] = '\r';
    buf[pos + len + 1] = '\n';
    buf[pos + len + 2] = 0;
    return pos + len;
}
