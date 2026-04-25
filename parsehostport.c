/*
 * parsehostport.c - Parse host[:port] strings into separate host and port.
 *
 * This module accepts hostnames and IPv4 literals with an optional explicit
 * port, raw IPv6 literals without a port, and bracketed IPv6 literals with or
 * without an explicit port. Explicit ports are validated with parseport_().
 * Any host form that uses brackets, or any unbracketed host containing more
 * than one ':', must be a syntactically valid IPv6 literal.
 */

#include <errno.h>
#include "log.h"
#include "parsehostport.h"
#include "parseip.h"
#include "parseport.h"

/*
 * parsehostport_split_ - Split a host[:port] string without copying output.
 *
 * @host: returned host pointer
 * @hostlen: returned host length
 * @port: returned port pointer
 * @portlen: returned port length
 * @bracketed: optional flag set for [IPv6] input
 * @coloncount: optional count of ':' characters in unbracketed input
 * @in: input string
 *
 * Splits unbracketed host[:port] forms, unbracketed multi-colon host forms,
 * and bracketed [host][:port] forms. For unbracketed input with more than one
 * ':', the helper returns the whole string as the host and leaves the port
 * empty. The returned slices point into @in and are not NUL terminated.
 *
 * This helper only separates host and port syntax. It does not validate that
 * the returned host or port slices are semantically valid.
 *
 * Constraints:
 *   - required output pointers and @in must be non-NULL
 */
static int parsehostport_split_(const char **host, long long *hostlen,
                                const char **port, long long *portlen,
                                int *bracketed, long long *coloncount,
                                const char *in) {

    long long i;
    long long len;
    long long localcoloncount;
    long long lastcolon;

    if (!host || !hostlen || !port || !portlen || !in) return 0;

    *host = 0;
    *hostlen = 0;
    *port = 0;
    *portlen = 0;
    if (bracketed) *bracketed = 0;
    if (coloncount) *coloncount = 0;

    if (!in[0]) return 0;

    if (in[0] == '[') {
        for (i = 1; in[i]; ++i) {
            if (in[i] == '[') return 0;
            if (in[i] == ']') break;
        }

        if (!in[i]) return 0;
        if (i == 1) return 0;

        *host = in + 1;
        *hostlen = i - 1;
        *port = in + i + 1;
        *portlen = 0;
        if (bracketed) *bracketed = 1;

        if (!in[i + 1]) return 1;
        if (in[i + 1] != ':') return 0;
        if (!in[i + 2]) return 0;

        for (len = i + 2; in[len]; ++len)
            if (in[len] == ']') return 0;

        *port = in + i + 2;
        *portlen = len - i - 2;
        return 1;
    }

    localcoloncount = 0;
    lastcolon = 0;
    for (len = 0; in[len]; ++len) {
        if (in[len] == ']') return 0;
        if (in[len] == ':') {
            ++localcoloncount;
            lastcolon = len;
        }
    }
    if (coloncount) *coloncount = localcoloncount;

    if (localcoloncount == 0) {
        *host = in;
        *hostlen = len;
        *port = in + len;
        *portlen = 0;
        return 1;
    }

    if (localcoloncount == 1) {
        if (lastcolon == 0) return 0;
        if (!in[lastcolon + 1]) return 0;

        *host = in;
        *hostlen = lastcolon;
        *port = in + lastcolon + 1;
        *portlen = len - lastcolon - 1;
        return 1;
    }

    *host = in;
    *hostlen = len;
    *port = in + len;
    *portlen = 0;
    return 1;
}

/*
 * parsehostport - Parse a host[:port] string into separate output buffers.
 *
 * @outhost: destination buffer for the host string
 * @outport: optional destination buffer for the port string
 * @hostport: input string
 *
 * Splits @hostport, validates the resulting host and optional port according
 * to the accepted syntax, and copies the results into separate NUL-terminated
 * buffers. If @outport is non-NULL and a port is present, it must satisfy
 * parseport_() validation, which accepts only canonical decimal values in the
 * range <0,65535>.
 *
 * When @outport is NULL, the function still requires the input to split
 * cleanly, but it neither validates nor returns the trailing port slice.
 *
 * Bracketed forms are reserved for IPv6 literals. After removing the brackets,
 * the host must pass parseip6_(). Unbracketed inputs with more than one ':'
 * are also treated as raw IPv6 literals and must pass parseip6_(). Other
 * unbracketed hosts are copied as returned by the splitter; this function does
 * not validate them as hostnames or IPv4 literals. In particular, a non-IPv6
 * host string is not validated to be a syntactically correct DNS name.
 *
 * Constraints:
 *   - @outhost must be non-NULL
 *   - destination buffers must match parsehostport_HOSTBYTES and
 *     parsehostport_PORTBYTES when provided
 */
int parsehostport(char *outhost, char *outport, const char *hostport) {

    const char *host;
    const char *port;
    long long hostlen;
    long long portlen;
    long long i;
    long long coloncount;
    int bracketed;
    char tmphost[parsehostport_HOSTBYTES] = {0};
    char tmpport[parsehostport_PORTBYTES] = {0};
    unsigned char ip[16];
    unsigned char portnum[2];

    if (!outhost) {
        errno = EINVAL;
        log_b1("parsehostport() called with outhost = (null)");
        return 0;
    }

    if (!hostport) goto err;
    if (!parsehostport_split_(&host, &hostlen, &port, &portlen, &bracketed,
                              &coloncount, hostport)) {
        goto err;
    }
    if (!outport) portlen = 0;
    if (hostlen >= parsehostport_HOSTBYTES) goto err;
    if (portlen >= parsehostport_PORTBYTES) goto err;

    for (i = 0; i < hostlen; ++i) tmphost[i] = host[i];
    tmphost[hostlen] = 0;
    /* A host using brackets or multiple unbracketed ':' must be raw IPv6. */
    if ((bracketed || coloncount > 1) && !parseip6_(ip, tmphost)) goto err;

    for (i = 0; i < portlen; ++i) tmpport[i] = port[i];
    tmpport[portlen] = 0;
    if (portlen && !parseport_(portnum, tmpport)) goto err;

    errno = 0;
    for (i = 0; i < parsehostport_HOSTBYTES; ++i) outhost[i] = tmphost[i];
    if (outport) {
        for (i = 0; i < parsehostport_PORTBYTES; ++i) outport[i] = tmpport[i];
        log_t7("'", log_str(hostport), "' parsed to host = '", log_str(outhost),
               "', port = '", log_str(outport), "'");
    }
    else {
        log_t5("'", log_str(hostport), "' parsed to host = '", log_str(outhost),
               "'");
    }
    return 1;

err:
    outhost[0] = 0;
    if (outport) outport[0] = 0;
    errno = EINVAL;
    log_e3("'", log_str(hostport), "' is not a valid 'host:port' string");
    return 0;
}
