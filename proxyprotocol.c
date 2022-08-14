/*
20211119
Jan Mojzis
Public domain.
*/

#include <unistd.h>
#include <string.h>
#include "e.h"
#include "log.h"
#include "str.h"
#include "buffer.h"
#include "stralloc.h"
#include "buf.h"
#include "jail.h"
#include "iptostr.h"
#include "strtoip.h"
#include "strtoport.h"
#include "porttostr.h"
#include "proxyprotocol.h"

int proxyprotocol_v1_get(int fd, unsigned char *localipx,
                         unsigned char *localportx, unsigned char *remoteipx,
                         unsigned char *remoteportx) {

    buffer sin = buffer_INIT(buffer_read, fd, /*no buffer*/ 0, /*no buffer*/ 0);
    int ret = 0;
    long long pos;
    char bufspace[PROXYPROTOCOL_MAX];
    char buforig[PROXYPROTOCOL_MAX];
    char *buf = bufspace;
    int (*strtoipop)(unsigned char *, const char *);
    unsigned char localip[16] = {0};
    unsigned char localport[2] = {0};
    unsigned char remoteip[16] = {0};
    unsigned char remoteport[2] = {0};

    log_t1("proxyprotocol_v1_get()");

    /* read proxy string byte-by-byte */
    for (pos = 0; pos < PROXYPROTOCOL_MAX - 1; ++pos) {
        if (buffer_GETC(&sin, &buf[pos]) != 1) goto cleanup;
        if (buf[pos] == '\n') break;
    }
    if (buf[pos] != '\n') goto cleanup;
    /*if (pos > 0 && buf[pos - 1] == '\r') --pos; */
    buf[pos + 1] = 0;
    memcpy(buforig, bufspace, PROXYPROTOCOL_MAX);

    /* header */
    if (str_start(buf, "PROXY UNKNOWN")) {
        ret = 1;
        goto cleanup;
    }
    else if (str_start(buf, "PROXY TCP4 ")) {
        strtoipop = strtoip4;
    }
    else if (str_start(buf, "PROXY TCP6 ")) {
        strtoipop = strtoip6;
    }
    else {
        log_e3("unable to parse proxy-protocol string '", buforig, "'");
        goto cleanup;
    }
    buf += 11;

    /* remote ip */
    pos = str_chr(buf, ' ');
    buf[pos] = 0;
    if (!strtoipop(remoteip, buf)) {
        log_e3("unable to parse remoteip from proxy-protocol string '",
               buforig, "'");
        goto cleanup;
    }
    buf += pos + 1;

    /* localip ip */
    pos = str_chr(buf, ' ');
    buf[pos] = 0;
    if (!strtoipop(localip, buf)) {
        log_e3("unable to parse localip from proxy-protocol string '", buforig,
               "'");
        goto cleanup;
    }
    buf += pos + 1;

    /* remote port */
    pos = str_chr(buf, ' ');
    buf[pos] = 0;
    if (!strtoport(remoteport, buf)) {
        log_e3("unable to parse remoteport from proxy-protocol string '",
               buforig, "'");
        goto cleanup;
    }
    buf += pos + 1;

    /* localport */
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
    log_t2("proxyprotocol_v1_get() = ", lognum(ret));
    return ret;
}

long long proxyprotocol_v1(char *buf, long long buflen, unsigned char *localip,
                           unsigned char *localport, unsigned char *remoteip,
                           unsigned char *remoteport) {

    stralloc sa = {0};
    long long ret = 0;

    if (!memcmp(localip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) &&
        !memcmp(remoteip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) &&
        !memcmp(localport, "\0\0", 2) && !memcmp(remoteport, "\0\0", 2)) {
        goto cleanup;
    }

    if (!memcmp("\0\0\0\0\0\0\0\0\0\0\377\377", remoteip, 12)) {
        if (!stralloc_cats(&sa, "PROXY TCP4 ")) goto cleanup;
    }
    else {
        if (!stralloc_cats(&sa, "PROXY TCP6 ")) goto cleanup;
    }
    if (!stralloc_cats(&sa, iptostr(0, remoteip))) goto cleanup;
    if (!stralloc_cats(&sa, " ")) goto cleanup;
    if (!stralloc_cats(&sa, iptostr(0,  localip))) goto cleanup;
    if (!stralloc_cats(&sa, " ")) goto cleanup;
    if (!stralloc_cats(&sa, porttostr(0,  remoteport))) goto cleanup;
    if (!stralloc_cats(&sa, " ")) goto cleanup;
    if (!stralloc_cats(&sa, porttostr(0,  localport))) goto cleanup;
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

long long proxyprotocol_v2(char *buf, long long buflen, unsigned char *localip,
                           unsigned char *localport, unsigned char *remoteip,
                           unsigned char *remoteport) {

    long long pos = 0;
    unsigned char ch;
    unsigned char len[2];
    int flagipv4 = 0;
    int flagipv6 = 0;

    if (!buf || buflen <= 0) goto fail;

    /* header */
    pos = buf_put(buf, buflen, pos,
                  "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
    if (!pos) goto fail;

    /* version + local/proxy  */
    ch = (2 << 4); /* version 2 */
    ch += 1;       /* proxy */
    pos = buf_put(buf, buflen, pos, &ch, 1);
    if (!pos) goto fail;

    /* address family */
    if (!memcmp(remoteip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12)) {
        ch = (1 << 4); /* IPv4 */
        len[0] = 0;
        len[1] = 12;
        flagipv4 = 1;
    }
    else {
        ch = (2 << 4); /* IPv6 */
        len[0] = 0;
        len[1] = 36;
        flagipv6 = 1;
    }
    /* transport protocol */
    ch += 1; /* stream */
    pos = buf_put(buf, buflen, pos, &ch, 1);
    if (!pos) goto fail;

    /* length */
    pos = buf_put(buf, buflen, pos, len, 2);
    if (!pos) goto fail;

    /* src ip */
    if (flagipv4) pos = buf_put(buf, buflen, pos, remoteip + 12, 4);
    if (flagipv6) pos = buf_put(buf, buflen, pos, remoteip, 16);
    if (!pos) goto fail;

    /* dst ip */
    if (flagipv4) pos = buf_put(buf, buflen, pos, localip + 12, 4);
    if (flagipv6) pos = buf_put(buf, buflen, pos, localip, 16);
    if (!pos) goto fail;

    /* src port */
    pos = buf_put(buf, buflen, pos, remoteport, 2);
    if (!pos) goto fail;

    /* dst port */
    pos = buf_put(buf, buflen, pos, localport, 2);
    if (!pos) goto fail;

    return pos;

fail:
    return 0;
}
