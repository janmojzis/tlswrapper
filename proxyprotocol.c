/*
20211119
Jan Mojzis
Public domain.
*/

#include <stdlib.h>
#include <string.h>
#include "strtoip.h"
#include "buf.h"
#include "iptostr.h"
#include "porttostr.h"
#include "strtoport.h"
#include "proxyprotocol.h"


long long proxyprotocol_v1(char *buf, long long buflen, unsigned char *localip, unsigned char *localport, unsigned char *remoteip, unsigned char *remoteport) {

    long long pos = 0;

    if (!buf || buflen <= 0) goto fail;

    if (!memcmp("\0\0\0\0\0\0\0\0\0\0\377\377", remoteip, 12)) {
        pos = buf_puts(buf, buflen, pos, "PROXY TCP4 ");
    }
    else {
        pos = buf_puts(buf, buflen, pos, "PROXY TCP6 ");
    }
    if (!pos) goto fail;

    pos = buf_puts(buf, buflen, pos, iptostr(0, remoteip));
    if (!pos) goto fail;
    pos = buf_puts(buf, buflen, pos, " ");
    if (!pos) goto fail;

    pos = buf_puts(buf, buflen, pos, iptostr(0, localip));
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

    return pos;

fail:
    return 0;
}


long long proxyprotocol_v2(char *buf, long long buflen, unsigned char *localip, unsigned char *localport, unsigned char *remoteip, unsigned char *remoteport) {

    long long pos = 0;
    unsigned char ch;
    unsigned char len[2];

    if (!buf || buflen <= 0) goto fail;

    /* header */
    pos = buf_put(buf, buflen, pos, (unsigned char *)"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
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
    }
    else {
        ch = (2 << 4); /* IPv6 */
        len[0] = 0;
        len[1] = 36;
    }
    /* transport protocol */
    ch += 1; /* stream */
    pos = buf_put(buf, buflen, pos, &ch, 1);
    if (!pos) goto fail;

    /* length */
    pos = buf_put(buf, buflen, pos, len, 2);
    if (!pos) goto fail;

    /* src ip */
    if (len[1] == 12) pos = buf_put(buf, buflen, pos, remoteip + 12, 4);
    if (len[1] == 36) pos = buf_put(buf, buflen, pos, remoteip, 16);
    if (!pos) goto fail;

    /* dst ip */
    if (len[1] == 12) pos = buf_put(buf, buflen, pos, localip + 12, 4);
    if (len[1] == 36) pos = buf_put(buf, buflen, pos, localip, 16);
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
