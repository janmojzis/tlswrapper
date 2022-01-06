/*
20130604
Jan Mojzis
Public domain.
*/

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include "iptostr.h"

/* convert IPv4 address */
static char *iptostr4(char *strbuf, const unsigned char *ip) {
    return (char *) inet_ntop(AF_INET, ip, strbuf, IPTOSTR_LEN);
}

/* convert IPv6 address */
static char *iptostr6(char *strbuf, const unsigned char *ip) {
    return (char *) inet_ntop(AF_INET6, ip, strbuf, IPTOSTR_LEN);
}

/*
The 'iptostr(strbuf,ip)' function converts IP address 'ip'
from network byte order into the 0-terminated string.
The 'ip' length is always 16 bytes. The caller must
allocate at least IPTOSTR_LEN bytes for 'strbuf'.
*/
char *iptostr(char *strbuf, const unsigned char *ip) {

    static char staticbuf[IPTOSTR_LEN];

    if (!strbuf) strbuf = staticbuf; /* not thread-safe */

    if (!memcmp("\0\0\0\0\0\0\0\0\0\0\377\377", ip, 12)) {
        return iptostr4(strbuf, ip + 12);
    }
    return iptostr6(strbuf, ip);
}
