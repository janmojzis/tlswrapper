#include "strtoport.h"
#include "hostport.h"

int hostport_parse(char *host, long long hostlen, unsigned char *port,
                   char *hostport) {

    long long i, j, colonpos, coloncount = 0;
    long long hostportlen;
    char ch;

    for (hostportlen = 0; hostport[hostportlen]; ++hostportlen)
        ;

    /* XXX */
    if (hostportlen > hostlen) return 0;

    /* IPv6 in brackets */
    if (hostportlen > 0 && hostport[0] == '[') {

        /* IPv6 */
        j = 0;
        for (i = 1; i < hostportlen; ++i) {
            ch = hostport[i];
            if (ch == ']') break;
            host[j++] = ch;
        }
        host[j] = 0;

        /* port */
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
