/*
20211119
Jan Mojzis
Public domain.
*/

#include <stdlib.h>
#include <string.h>
#include "strtoip.h"
#include "iptostr.h"
#include "porttostr.h"
#include "strtoport.h"
#include "connectioninfo.h"
#include "proxyprotocol.h"


static size_t add(char *buf, size_t buflen, size_t pos, unsigned char *x, size_t len) {

    if (!x) return 0;
    if (pos + len >= buflen) return 0;

    memcpy(buf + pos, x, len);
    return pos + len;
}

static size_t add_str(char *buf, size_t buflen, size_t pos, char *x) {
    return add(buf, buflen, pos, (unsigned char *)x, strlen(x));
}

int proxyprotocol_v1(char *buf, size_t buflen) {

    unsigned char localip[16] = {0};
    unsigned char localport[2] = {0};
    unsigned char remoteip[16] = {0};
    unsigned char remoteport[2] = {0};
    size_t pos = 0;

    if (!connectioninfo(localip, localport, remoteip, remoteport)) goto fail;

    if (!memcmp("\0\0\0\0\0\0\0\0\0\0\377\377", remoteip, 12)) {
        pos = add_str(buf, buflen, pos, "PROXY TCP4 ");
    }
    else {
        pos = add_str(buf, buflen, pos, "PROXY TCP6 ");
    }
    if (!pos) goto fail;

    pos = add_str(buf, buflen, pos, iptostr(0, remoteip));
    if (!pos) goto fail;
    pos = add_str(buf, buflen, pos, " ");
    if (!pos) goto fail;

    pos = add_str(buf, buflen, pos, iptostr(0, localip));
    if (!pos) goto fail;
    pos = add_str(buf, buflen, pos, " ");
    if (!pos) goto fail;

    pos = add_str(buf, buflen, pos, porttostr(0, remoteport));
    if (!pos) goto fail;
    pos = add_str(buf, buflen, pos, " ");
    if (!pos) goto fail;

    pos = add_str(buf, buflen, pos, porttostr(0, localport));
    if (!pos) goto fail;

    pos = add_str(buf, buflen, pos, "\r\n");
    if (!pos) goto fail;

    return pos;

fail:
    return 0;
}


int proxyprotocol_v2(char *buf, size_t buflen) {

    size_t pos = 0;
    unsigned char ch;
    unsigned char len[2];

    unsigned char localip[16] = {0};
    unsigned char localport[2] = {0};
    unsigned char remoteip[16] = {0};
    unsigned char remoteport[2] = {0};

    if (!connectioninfo(localip, localport, remoteip, remoteport)) goto fail;

    /* header */
    pos = add(buf, buflen, pos, (unsigned char *)"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
    if (!pos) goto fail;

    /* version + local/proxy  */
    ch = (2 << 4); /* version 2 */
    ch += 1; /* proxy */
    pos = add(buf, buflen, pos, &ch, 1);
    if (!pos) goto fail;

    /* address family */
    if (!memcmp(remoteip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12)) {
        ch = (1 << 4); /* IPv4 */
        len[0] = 0;
        len[1] = 12;
    }
    else {
        ch = (2 << 4); /* IPv6 */
        len[0] = 0;
        len[1] = 36;
    }
    /* transport protocol */
    ch += 1; /* stream */
    pos = add(buf, buflen, pos, &ch, 1);
    if (!pos) goto fail;

    /* length */
    pos = add(buf, buflen, pos, len, 2);
    if (!pos) goto fail;

    /* src ip */
    if (len[1] == 12) pos = add(buf, buflen, pos, remoteip + 12, 4);
    if (len[1] == 36) pos = add(buf, buflen, pos, remoteip, 16);
    if (!pos) goto fail;

    /* dst ip */
    if (len[1] == 12) pos = add(buf, buflen, pos, localip + 12, 4);
    if (len[1] == 36) pos = add(buf, buflen, pos, localip, 16);
    if (!pos) goto fail;

    /* src port */
    pos = add(buf, buflen, pos, remoteport, 2);
    if (!pos) goto fail;

    /* dst port */
    pos = add(buf, buflen, pos, localport, 2);
    if (!pos) goto fail;

    return pos;

fail:
    return 0;
}
