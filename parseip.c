/*
 * parseip.c - Parse IPv4/IPv6 literals into 16-byte buffers.
 *
 * This module parses textual IP address literals into a 16-byte representation.
 * IPv4 addresses are stored as IPv4-mapped IPv6 (::ffff:a.b.c.d); IPv6
 * addresses are stored unchanged. The low-level parsers return 1/0; the public
 * wrapper logs and sets errno on error.
 */

#include <arpa/inet.h>
#include <string.h>
#include "e.h"
#include "log.h"
#include "parseip.h"

/*
 * parseip6_ - Parse an IPv6 literal into a 16-byte buffer.
 *
 * @ip: output buffer (16 bytes); NULL is rejected
 * @ipstr: input string (IPv6 literal, NUL-terminated); NULL is rejected
 *
 * Returns 1 on success, 0 on error.
 */
int parseip6_(unsigned char *ip, const char *ipstr) {

    if (!ip || !ipstr) return 0;
    if (inet_pton(AF_INET6, ipstr, ip) == 1) return 1;
    return 0;
}

/*
 * parseip4_ - Parse an IPv4 literal into a v4-mapped 16-byte buffer.
 *
 * @ip: output buffer (16 bytes), receives ::ffff:IPv4; NULL is rejected
 * @ipstr: input string (IPv4 literal, NUL-terminated); NULL is rejected
 *
 * Returns 1 on success, 0 on error.
 */
int parseip4_(unsigned char *ip, const char *ipstr) {

    if (!ip || !ipstr) return 0;
    if (inet_pton(AF_INET, ipstr, ip + 12) == 1) {
        memcpy(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
        return 1;
    }
    return 0;
}

/*
 * parseip - Parse IPv4/IPv6 literal into a 16-byte buffer.
 *
 * @ip: output buffer (16 bytes)
 * @ipstr: input string (IPv4 or IPv6 literal, NUL-terminated)
 *
 * Returns 1 on success, 0 on error (errno set to EINVAL).
 * Logs a tracing message on success and an error on failure.
 */
int parseip(unsigned char *ip, const char *ipstr) {

    if (!ip) {
        errno = EINVAL;
        log_b1("parseip() called with ip = (null)");
        return 0;
    }

    if (!ipstr) goto err;
    if (parseip4_(ip, ipstr)) {
        errno = 0;
        log_t4("'", log_str(ipstr), "' parsed to IPv4 ", log_ip(ip));
        return 1;
    }
    if (parseip6_(ip, ipstr)) {
        errno = 0;
        log_t4("'", log_str(ipstr), "' parsed to IPv6 ", log_ip(ip));
        return 1;
    }

err:
    errno = EINVAL;
    log_e3("'", log_str(ipstr), "' is not a valid IP address");
    return 0;
}
