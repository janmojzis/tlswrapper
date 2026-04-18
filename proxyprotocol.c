/*
 * proxyprotocol.c - parse and generate HAProxy PROXY protocol v1 headers
 *
 * Provides helpers for receiving a textual PROXY protocol v1 line from a
 * file descriptor and for serializing local/remote endpoint addresses back
 * into the same wire format. The implementation supports TCP over IPv4 and
 * IPv6 and treats "PROXY UNKNOWN" as a valid header without endpoint data.
 */

#include <unistd.h>
#include <string.h>
#include "e.h"
#include "log.h"
#include "str.h"
#include "buffer.h"
#include "stralloc.h"
#include "jail.h"
#include "iptostr.h"
#include "strtoip.h"
#include "strtoport.h"
#include "porttostr.h"
#include "proxyprotocol.h"

/*
 * proxyprotocol_v1_get - read and parse a PROXY protocol v1 header
 *
 * @fd: file descriptor to read the header from
 * @localipx: output buffer for the destination IP address
 * @localportx: output buffer for the destination port
 * @remoteipx: output buffer for the source IP address
 * @remoteportx: output buffer for the source port
 *
 * Reads a single CRLF-terminated PROXY protocol v1 line from @fd and parses
 * IPv4 or IPv6 endpoint fields into the library's internal address format.
 * The function accepts "PROXY UNKNOWN" and returns success without filling
 * endpoint data.
 *
 * Constraints:
 *   - Output buffers must have room for 16-byte IP addresses and 2-byte ports.
 *   - The header must fit within PROXYPROTOCOL_MAX bytes including CRLF.
 *
 * Returns 1 on success and 0 on parse or I/O failure.
 */
int proxyprotocol_v1_get(int fd, unsigned char *localipx,
                         unsigned char *localportx, unsigned char *remoteipx,
                         unsigned char *remoteportx) {

    buffer sin = buffer_INIT(buffer_read, fd, /*no buffer*/ 0, /*no buffer*/ 0);
    int ret = 0;
    long long pos;
    char bufspace[PROXYPROTOCOL_MAX] = {0};
    char buforig[PROXYPROTOCOL_MAX];
    char *buf = bufspace;
    int (*strtoipop)(unsigned char *, const char *);
    unsigned char localip[16] = {0};
    unsigned char localport[2] = {0};
    unsigned char remoteip[16] = {0};
    unsigned char remoteport[2] = {0};

    log_t1("proxyprotocol_v1_get()");

    /* Read until LF so short partial headers do not overrun the fixed buffer.
     */
    for (pos = 0; pos < PROXYPROTOCOL_MAX - 1; ++pos) {
        if (buffer_GETC(&sin, &buf[pos]) != 1) {
            log_e1("unable to read proxy-protocol string");
            goto cleanup;
        }
        if (buf[pos] == '\n') break;
    }
    if (buf[pos] != '\n') {
        errno = EPROTO;
        log_e1("unable to read proxy-protocol string, no CRLF");
        goto cleanup;
    }
    /*if (pos > 0 && buf[pos - 1] == '\r') --pos; */
    buf[pos + 1] = 0;
    memcpy(buforig, bufspace, PROXYPROTOCOL_MAX);

    /* Dispatch by protocol family after the fixed "PROXY " prefix. */
    if (str_start(buf, "PROXY UNKNOWN")) {
        ret = 1;
        goto cleanup;
    }
    else if (str_start(buf, "PROXY TCP4 ")) { strtoipop = strtoip4; }
    else if (str_start(buf, "PROXY TCP6 ")) { strtoipop = strtoip6; }
    else {
        log_e3("unable to parse proxy-protocol string '", buforig, "'");
        goto cleanup;
    }
    buf += 11;

    /* Parse the source endpoint first, matching the wire format order. */
    pos = str_chr(buf, ' ');
    buf[pos] = 0;
    if (!strtoipop(remoteip, buf)) {
        log_e3("unable to parse remoteip from proxy-protocol string '", buforig,
               "'");
        goto cleanup;
    }
    buf += pos + 1;

    /* Parse the destination IP address. */
    pos = str_chr(buf, ' ');
    buf[pos] = 0;
    if (!strtoipop(localip, buf)) {
        log_e3("unable to parse localip from proxy-protocol string '", buforig,
               "'");
        goto cleanup;
    }
    buf += pos + 1;

    /* Parse the source port. */
    pos = str_chr(buf, ' ');
    buf[pos] = 0;
    if (!strtoport(remoteport, buf)) {
        log_e3("unable to parse remoteport from proxy-protocol string '",
               buforig, "'");
        goto cleanup;
    }
    buf += pos + 1;

    /* Parse the destination port and ignore the trailing CRLF. */
    buf[str_chr(buf, '\n')] = 0;
    buf[str_chr(buf, '\r')] = 0;
    if (!strtoport(localport, buf)) {
        log_e3("unable to parse localport from proxy-protocol string '",
               buforig, "'");
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (ret) {
        memcpy(localipx, localip, 16);
        memcpy(remoteipx, remoteip, 16);
        memcpy(localportx, localport, 2);
        memcpy(remoteportx, remoteport, 2);
    }
    log_t2("proxyprotocol_v1_get() = ", log_num(ret));
    return ret;
}

/*
 * proxyprotocol_v1 - serialize endpoint data into a PROXY protocol v1 header
 *
 * @buf: destination buffer, or null to query the required output length
 * @buflen: size of @buf in bytes
 * @localip: destination IP address in internal format
 * @localport: destination port in network byte order
 * @remoteip: source IP address in internal format
 * @remoteport: source port in network byte order
 *
 * Builds a textual PROXY protocol v1 line for IPv4 or IPv6 based on the
 * endpoint addresses. When all addresses and ports are zero, the function
 * returns 0 and emits no header.
 *
 * Constraints:
 *   - @buf may be null when the caller only wants the encoded length.
 *   - The header is copied only when @buflen is large enough for the result.
 *
 * Returns the encoded header length on success, or 0 when no header was
 * generated or memory allocation failed.
 */
long long proxyprotocol_v1(char *buf, long long buflen, unsigned char *localip,
                           unsigned char *localport, unsigned char *remoteip,
                           unsigned char *remoteport) {

    stralloc sa = {0};
    long long ret = 0;

    /* Suppress the header when connection metadata is not available. */
    if (!memcmp(localip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) &&
        !memcmp(remoteip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) &&
        !memcmp(localport, "\0\0", 2) && !memcmp(remoteport, "\0\0", 2)) {
        goto cleanup;
    }

    /* IPv4 addresses are stored as IPv4-mapped IPv6 values. */
    if (!memcmp("\0\0\0\0\0\0\0\0\0\0\377\377", remoteip, 12)) {
        if (!stralloc_copys(&sa, "PROXY TCP4 ")) goto cleanup;
    }
    else {
        if (!stralloc_copys(&sa, "PROXY TCP6 ")) goto cleanup;
    }
    if (!stralloc_cats(&sa, iptostr(0, remoteip))) goto cleanup;
    if (!stralloc_cats(&sa, " ")) goto cleanup;
    if (!stralloc_cats(&sa, iptostr(0, localip))) goto cleanup;
    if (!stralloc_cats(&sa, " ")) goto cleanup;
    if (!stralloc_cats(&sa, porttostr(0, remoteport))) goto cleanup;
    if (!stralloc_cats(&sa, " ")) goto cleanup;
    if (!stralloc_cats(&sa, porttostr(0, localport))) goto cleanup;
    if (!stralloc_cats(&sa, "\r\n")) goto cleanup;
    if (!stralloc_0(&sa)) goto cleanup;
    --sa.len;
    if (buf && buflen >= sa.len) {
        memcpy(buf, sa.s, sa.len);
        ret = sa.len;
    }

cleanup:
    stralloc_free(&sa);
    return ret;
}
