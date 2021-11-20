#include <stdlib.h>
#include <string.h>
#include "strtoip.h"
#include "iptostr.h"
#include "porttostr.h"
#include "portparse.h"
#include "connectioninfo.h"
#include "proxyprotocol.h"

static size_t add_str(char *buf, size_t buflen, size_t pos, char *x) {

    size_t i, len = strlen(x);

    if (!x) return 0;
    if (pos + len >= buflen) return 0;

    for (i = 0; i < len; ++i) {
        if (x[i] < 32 || x[i] > 126)
            buf[pos + i] = '?';
        else
            buf[pos + i] = x[i];
    }

    return pos + len;
}
#define ADD_STR(a, b, c, d) { pos = add((a), (b,) (c), (d)); if (!pos) goto fail; }

static size_t add(char *buf, size_t buflen, size_t pos, char *x, size_t len) {

    if (!x) return 0;
    if (pos + len >= buflen) return 0;

    memcpy(buf + pos, x, len);
    return pos + len;
}
#define ADD(a, b, c, d, e) { pos = add((a), (b,) (c), (d), (e)); if (!pos) goto fail; }

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

    pos = add(buf, buflen, pos, "\r\n", 2);
    if (!pos) goto fail;

    return pos;

fail:
    return 0;
}


int proxyprotocol_v2(char *buf, size_t buflen) {

    size_t pos = 0;
    char ch;
    unsigned char len[2];

    unsigned char localip[16] = {0};
    unsigned char localport[2] = {0};
    unsigned char remoteip[16] = {0};
    unsigned char remoteport[2] = {0};

    if (!connectioninfo(localip, localport, remoteip, remoteport)) goto fail;

    /* header */
    pos = add(buf, buflen, pos, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
    if (!pos) goto fail;

    /* version */
    ch = (2 << 4);
    /* local/proxy */
    ch += 1;
    pos = add(buf, buflen, pos, &ch, 1);
    if (!pos) goto fail;

    /* address family */
    if (memcmp(remoteip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12)) {
        /* IPv6 */
        ch = (2 << 4);
        len[0] = 0;
        len[1] = 36;
    }
    else {
        /* IPv4 */
        ch = (1 << 4);
        len[0] = 0;
        len[1] = 12;
    }

    /* transport protocol */
    ch += 1;
    pos = add(buf, buflen, pos, &ch, 1);
    if (!pos) goto fail;

    /* length */
    pos = add(buf, buflen, pos, (char *)len, 2);
    if (!pos) goto fail;

    /* src ip */
    if (len[1] == 12) pos = add(buf, buflen, pos, (char *)remoteip + 12, 4);
    if (len[1] == 36) pos = add(buf, buflen, pos, (char *)remoteip, 16);
    if (!pos) goto fail;

    /* dst ip */
    if (len[1] == 12) pos = add(buf, buflen, pos, (char *)localip + 12, 4);
    if (len[1] == 36) pos = add(buf, buflen, pos, (char *)localip, 16);
    if (!pos) goto fail;

    /* src port */
    pos = add(buf, buflen, pos, (char *)remoteport, 2);
    if (!pos) goto fail;

    /* dst port */
    pos = add(buf, buflen, pos, (char *)localport, 2);
    if (!pos) goto fail;

    return pos;

fail:
    return 0;
}
