/*
 * iptostr.c - convert binary IP addresses to presentation strings
 *
 * Provides helpers for formatting IPv6 addresses and IPv4-mapped IPv6
 * addresses into NUL-terminated strings.
 */

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include "iptostr.h"

static const char *iptostr4(char *strbuf, const unsigned char *ip) {
    return inet_ntop(AF_INET, ip, strbuf, IPTOSTR_LEN);
}

static const char *iptostr6(char *strbuf, const unsigned char *ip) {
    return inet_ntop(AF_INET6, ip, strbuf, IPTOSTR_LEN);
}

/*
 * iptostr - convert a binary IP address to a presentation string
 *
 * @strbuf: destination buffer, or NULL to use the internal static buffer
 * @ip: 16-byte IP address in network byte order
 *
 * Converts ip to a NUL-terminated string and returns the pointer returned
 * by inet_ntop(). IPv4-mapped IPv6 addresses are formatted as IPv4.
 *
 * Constraints:
 *   - ip must reference at least 16 readable bytes
 *   - strbuf must provide at least IPTOSTR_LEN bytes when not NULL
 *
 * Security:
 *   - passing NULL for strbuf uses a shared static buffer and is not
 *     thread-safe
 */
const char *iptostr(char *strbuf, const unsigned char *ip) {

    static char staticbuf[IPTOSTR_LEN];

    if (!strbuf) strbuf = staticbuf; /* not thread-safe */

    if (!memcmp("\0\0\0\0\0\0\0\0\0\0\377\377", ip, 12)) {
        return iptostr4(strbuf, ip + 12);
    }
    return iptostr6(strbuf, ip);
}
