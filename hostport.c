/*
 * hostport.c - split host:port strings into separate fields
 *
 * The parser accepts bracketed IPv6 literals and simple host:port input
 * and stores the port in the project's two-byte format.
 */

#include "strtoport.h"
#include "hostport.h"

/*
 * hostport_parse - split a host/port string
 *
 * @host: destination buffer for the host name
 * @hostlen: capacity of @host
 * @port: two-byte output buffer for the parsed port
 * @hostport: mutable input string
 *
 * Returns 1 on success. Bracketed IPv6 literals are unwrapped before the
 * port is parsed.
 *
 * Constraints:
 *   - host must provide room for the copied host and its trailing NUL
 */
int hostport_parse(char *host, long long hostlen, unsigned char *port,
                   char *hostport) {

    long long i, j, colonpos = 0, coloncount = 0;
    long long hostportlen;
    char ch;

    for (hostportlen = 0; hostport[hostportlen]; ++hostportlen);

    /* Reject inputs that cannot fit in the destination host buffer. */
    if (hostportlen > hostlen) return 0;

    /* Bracketed IPv6 literals keep colons out of the host/port split. */
    if (hostportlen > 0 && hostport[0] == '[') {

        j = 0;
        for (i = 1; i < hostportlen; ++i) {
            ch = hostport[i];
            if (ch == ']') break;
            host[j++] = ch;
        }
        host[j] = 0;

        if ((i + 2) >= hostportlen) return 0;
        if (hostport[i + 1] != ':') return 0;
        return strtoport(port, hostport + i + 2);
    }

    for (i = 0; i < hostportlen; ++i) {
        host[i] = hostport[i];
        if (hostport[i] == ':') {
            colonpos = i;
            ++coloncount;
        }
    }
    if (coloncount != 1) return 0;
    host[colonpos] = 0;

    return strtoport(port, hostport + colonpos + 1);
}
