/*
20211119
Jan Mojzis
Public domain.
*/

#include <unistd.h>
#include <string.h>
#include "jail.h"
#include "buf.h"
#include "e.h"
#include "log.h"
#include "strtoip.h"
#include "strtoport.h"
#include "iptostr.h"
#include "porttostr.h"
#include "proxyprotocol.h"

static int getch(int fd, char *x) {

    int r;
    struct pollfd p;

    for (;;) {
        r = read(fd, x, 1);
        if (r == -1) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                p.fd = fd;
                p.events = POLLIN | POLLERR;
                jail_poll(&p, 1, -1);
                continue;
            }
        }
        break;
    }
    return r;
}

static long long str_chr(const char *s, int c) {

    long long i;
    char ch = c;

    for (i = 0; s[i]; ++i) if (s[i] == ch) break;
    return i;
}

static int str_start(const char *s, const char *t) {

    char x;

    for (;;) {
        x = *t++;
        if (!x) return 1;
        if (x != *s++) return 0;
    }
}

static int proxyprotocol1_parse(char *buforig, unsigned char *localipx, unsigned char *localportx, unsigned char *remoteipx, unsigned char *remoteportx) {

    int ret = 0;
    long long pos;
    unsigned long i;
    char bufspace[PROXYPROTOCOL_MAX];
    char *buf = bufspace;
    int (*strtoipop)(unsigned char *, const char *);
    unsigned char localip[16] = {0};
    unsigned char localport[2] = {0};
    unsigned char remoteip[16] = {0};
    unsigned char remoteport[2] = {0};

    log_t3("proxyprotocol1_parse = ('", buforig, "')");

    /* copy string to new buffer */
    for (i = 0; i < sizeof bufspace - 1 && buforig[i]; ++i) {
        bufspace[i] = buforig[i];
    }
    bufspace[i] = 0;

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
        log_e3("unable to parse remoteip from proxy-protocol string '", buforig, "'");
        goto cleanup;
    }
    buf += pos + 1;

    /* localip ip */ 
    pos = str_chr(buf, ' ');
    buf[pos] = 0;
    if (!strtoipop(localip, buf)) {
        log_e3("unable to parse localip from proxy-protocol string '", buforig, "'");
        goto cleanup;
    }
    buf += pos + 1;

    /* remote port */
    pos = str_chr(buf, ' ');
    buf[pos] = 0;
    if (!strtoport(remoteport, buf)) {
        log_e3("unable to parse repoteport from proxy-protocol string '", buforig, "'");
        goto cleanup;
    }
    buf += pos + 1;

    /* localport */
    buf[str_chr(buf, '\n')] = 0;
    buf[str_chr(buf, '\r')] = 0;
    if (!strtoport(localport, buf)) {
        log_e3("unable to parse localport from proxy-protocol string '", buforig, "'");
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
    log_t4("proxyprotocol1_parse = ('", buforig, "') = ", lognum(ret));
    return ret;
}


int proxyprotocol_v1_get(int fd, unsigned char *localip, unsigned char *localport, unsigned char *remoteip, unsigned char *remoteport) {

    char ch, buf[PROXYPROTOCOL_MAX];
    int r;
    long long pos = 0;

    for (;;) {
        r = getch(fd, &ch);
        if (r != 1) return 0;
        pos = buf_put(buf, sizeof buf, pos, &ch, 1);
        if (!pos) return 0;
        if (ch == '\n') break;
    }
    errno = 0;
    pos = buf_put(buf, sizeof buf, pos, "", 1);
    if (!pos) return 0;
    return proxyprotocol1_parse(buf, localip, localport, remoteip, remoteport);
}


static long long putip6(void *buf, long long buflen, long long pos, const unsigned char *ip) {

    long long i;
    char ch[2];

    for (i = 0; i < 16; ++i) {
        ch[0] = "0123456789abcdef"[(ip[i] >> 4) & 15];
        ch[1] = "0123456789abcdef"[ip[i]        & 15];
        pos = buf_put(buf, buflen, pos, ch, 2);
        if (!pos) break;
        if (i < 15 && i % 2) {
            pos = buf_put(buf, buflen, pos, ":", 1);
            if (!pos) break;
        }
    }
    return pos;
}

static long long putip4(void *buf, long long buflen, long long pos, const unsigned char *ip) {
    return buf_puts(buf, buflen, pos, iptostr(0, ip));
}
long long proxyprotocol_v1(char *buf, long long buflen, unsigned char *localip, unsigned char *localport, unsigned char *remoteip, unsigned char *remoteport) {

    long long pos = 0;
    long long (*putip)(void *, long long, long long, const unsigned char *);

    if (!buf || buflen < PROXYPROTOCOL_MAX) return 0;

    if (!memcmp(localip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) &&
        !memcmp(remoteip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) &&
        !memcmp(localport, "\0\0", 2) &&
        !memcmp(remoteport, "\0\0", 2)) {
        goto fail;
    }

    if (!memcmp("\0\0\0\0\0\0\0\0\0\0\377\377", remoteip, 12)) {
        pos = buf_puts(buf, buflen, pos, "PROXY TCP4 ");
        putip = putip4;
    }
    else {
        pos = buf_puts(buf, buflen, pos, "PROXY TCP6 ");
        putip = putip6;
    }
    if (!pos) goto fail;

    pos = putip(buf, buflen, pos, remoteip);
    if (!pos) goto fail;
    pos = buf_puts(buf, buflen, pos, " ");
    if (!pos) goto fail;

    pos = putip(buf, buflen, pos, localip);
    if (!pos) goto fail;
    pos = buf_puts(buf, buflen, pos, " ");
    if (!pos) goto fail;

    pos = buf_puts(buf, buflen, pos, porttostr(0, remoteport));
    if (!pos) goto fail;
    pos = buf_puts(buf, buflen, pos, " ");
    if (!pos) goto fail;

    pos = buf_puts(buf, buflen, pos, porttostr(0, localport));
    if (!pos) goto fail;

    pos = buf_puts(buf, buflen, pos, "\r\n");
    if (!pos) goto fail;

    pos = buf_put(buf, buflen, pos, "", 1);
    if (!pos) goto fail;

    return pos - 1;

fail:
    pos = 0;
    pos = buf_puts(buf, buflen, pos, "PROXY UNKNOWN\r\n");
    pos = buf_put(buf, buflen, pos, "", 1);
    return pos - 1;
}


long long proxyprotocol_v2(char *buf, long long buflen, unsigned char *localip, unsigned char *localport, unsigned char *remoteip, unsigned char *remoteport) {

    long long pos = 0;
    unsigned char ch;
    unsigned char len[2];
    int flagipv4 = 0;
    int flagipv6 = 0;

    if (!buf || buflen <= 0) goto fail;

    /* header */
    pos = buf_put(buf, buflen, pos, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
    if (!pos) goto fail;

    /* version + local/proxy  */
    ch = (2 << 4); /* version 2 */
    ch += 1; /* proxy */
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
