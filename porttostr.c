/*
 * porttostr.c - convert binary TCP/UDP ports to decimal strings
 *
 * Provides a small formatter for two-byte network-order port values and
 * returns their NUL-terminated decimal representation.
 */

#include <stdint.h>
#include "porttostr.h"

/*
 * porttostr - convert a two-byte network-order port to a decimal string
 *
 * @strbuf: destination buffer, or NULL to use the internal static buffer
 * @port: two-byte port value in network byte order
 *
 * Converts the port number to a NUL-terminated decimal string and returns
 * a pointer to the first output byte.
 *
 * Constraints:
 *   - port must reference at least 2 readable bytes
 *   - strbuf must provide at least PORTTOSTR_LEN bytes when not NULL
 *
 * Security:
 *   - passing NULL for strbuf uses a shared static buffer and is not
 *     thread-safe
 */
char *porttostr(char *strbuf, const unsigned char *port) {

    long long len = 0;
    uint16_t num;
    static char staticbuf[PORTTOSTR_LEN];

    if (!strbuf) strbuf = staticbuf; /* not thread-safe */

    num = port[0];
    num <<= 8;
    num |= port[1];
    do {
        num /= 10;
        ++len;
    } while (num);
    strbuf += len;

    num = port[0];
    num <<= 8;
    num |= port[1];
    do {
        *--strbuf = '0' + (num % 10);
        num /= 10;
    } while (num);

    while (len < PORTTOSTR_LEN) strbuf[len++] = 0;
    return strbuf;
}
