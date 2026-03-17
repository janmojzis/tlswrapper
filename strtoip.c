/*
 * strtoip.c - parse textual IP addresses into 16-byte storage
 *
 * The module accepts IPv4 and IPv6 input and stores IPv4 addresses in
 * IPv4-mapped IPv6 form.
 */

#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "strtoip.h"

/*
 * strtoip4 - parse an IPv4 address into IPv4-mapped IPv6 form
 *
 * @ip: 16-byte output buffer
 * @x: input string
 *
 * Returns 1 on success. The first 12 bytes are set to the fixed
 * IPv4-mapped prefix.
 */
int strtoip4(unsigned char *ip, const char *x) {

    if (!x) return 0;
    if (inet_pton(AF_INET, x, ip + 12) != 1) return 0;
    memcpy(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
    return 1;
}

/*
 * strtoip6 - parse an IPv6 address
 *
 * @ip: 16-byte output buffer
 * @x: input string
 *
 * Returns 1 on success and stores the raw IPv6 address in @ip.
 */
int strtoip6(unsigned char *ip, const char *x) {

    if (!x) return 0;
    if (inet_pton(AF_INET6, x, ip) != 1) return 0;
    return 1;
}

/*
 * strtoip - parse either IPv4 or IPv6 input
 *
 * @ip: 16-byte output buffer
 * @x: input string
 *
 * Tries IPv4 first and then IPv6. Returns 1 when either parser accepts
 * the input string.
 */
int strtoip(unsigned char *ip, const char *x) {

    if (strtoip4(ip, x)) return 1;
    if (strtoip6(ip, x)) return 1;
    return 0;
}
