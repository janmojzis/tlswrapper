/*
 * strtoport.c - parse decimal TCP/UDP port numbers
 *
 * This module converts a decimal string into the two-byte network-order
 * format used by the rest of the codebase.
 */

#include "strtoport.h"

/*
 * strtoport - parse a decimal port string
 *
 * @y: two-byte output buffer
 * @x: NUL-terminated decimal string
 *
 * Returns 1 on success. Rejects empty strings, trailing characters, and
 * values outside the 0..65535 range.
 */
int strtoport(unsigned char *y, const char *x) {

    long long j, d = 0;

    if (!x) return 0;
    for (j = 0; j < 5 && x[j] >= '0' && x[j] <= '9'; ++j) {
        d = d * 10 + (x[j] - '0');
    }
    if (j == 0) return 0;
    if (x[j]) return 0;
    if (d > 65535) return 0;
    y[0] = d >> 8;
    y[1] = d;

    return 1;
}
