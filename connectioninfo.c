/*
 * connectioninfo.c - load and export TCP endpoint metadata
 *
 * Provides helpers that read local and remote endpoint addresses either
 * from inherited environment variables or from the connected socket and
 * export them in the project's normalized binary and string formats.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "strtoip.h"
#include "strtoport.h"
#include "porttostr.h"
#include "iptostr.h"
#include "log.h"
#include "connectioninfo.h"

/*
 * connectioninfo_fromfd - read endpoint metadata from the connected socket
 *
 * @localip: 16-byte output buffer for the local address
 * @localport: two-byte output buffer for the local port
 * @remoteip: 16-byte output buffer for the peer address
 * @remoteport: two-byte output buffer for the peer port
 *
 * Reads socket metadata from descriptor 0 with getsockname() and
 * getpeername(). IPv4 addresses are stored as IPv4-mapped IPv6 values.
 */
static int connectioninfo_fromfd(unsigned char *localip,
                                 unsigned char *localport,
                                 unsigned char *remoteip,
                                 unsigned char *remoteport) {

    int fd = 0;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof sa;

    if (getsockname(fd, (struct sockaddr *) &sa, &salen) == -1) return 0;

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &sa;
        memcpy(localip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
        memcpy(localip + 12, &sin->sin_addr, 4);
        memcpy(localport, &sin->sin_port, 2);
    }
    else if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sa;
        memcpy(localip, &sin6->sin6_addr, 16);
        memcpy(localport, &sin6->sin6_port, 2);
    }
    else { return 0; }

    salen = sizeof sa;
    if (getpeername(fd, (struct sockaddr *) &sa, &salen) == -1) return 0;

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &sa;
        memcpy(remoteip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
        memcpy(remoteip + 12, &sin->sin_addr, 4);
        memcpy(remoteport, &sin->sin_port, 2);
    }
    else if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sa;
        memcpy(remoteip, &sin6->sin6_addr, 16);
        memcpy(remoteport, &sin6->sin6_port, 2);
    }
    else { return 0; }
    log_t4("connectioninfo_fromfd(): local=", log_ipport(localip, localport),
           ", remote=", log_ipport(remoteip, remoteport));
    return 1;
}

/*
 * connectioninfo_fromenv - read endpoint metadata from environment variables
 *
 * @localip: 16-byte output buffer for the local address
 * @localport: two-byte output buffer for the local port
 * @remoteip: 16-byte output buffer for the peer address
 * @remoteport: two-byte output buffer for the peer port
 *
 * Parses TCPLOCALIP, TCPLOCALPORT, TCPREMOTEIP, and TCPREMOTEPORT into the
 * project's normalized binary formats.
 */
static int connectioninfo_fromenv(unsigned char *localip,
                                  unsigned char *localport,
                                  unsigned char *remoteip,
                                  unsigned char *remoteport) {

    if (!strtoip(localip, getenv("TCPLOCALIP"))) return 0;
    if (!strtoport(localport, getenv("TCPLOCALPORT"))) return 0;
    if (!strtoip(remoteip, getenv("TCPREMOTEIP"))) return 0;
    if (!strtoport(remoteport, getenv("TCPREMOTEPORT"))) return 0;
    log_t4("connectioninfo_fromenv(): local=", log_ipport(localip, localport),
           ", remote=", log_ipport(remoteip, remoteport));
    return 1;
}

/*
 * connectioninfo_get - populate endpoint metadata from env or socket state
 *
 * @localip: 16-byte output buffer for the local address
 * @localport: two-byte output buffer for the local port
 * @remoteip: 16-byte output buffer for the peer address
 * @remoteport: two-byte output buffer for the peer port
 *
 * First attempts to load the endpoint data from environment variables and
 * falls back to querying descriptor 0 when the variables are unavailable.
 *
 * Returns 1 on success and 0 on failure.
 */
int connectioninfo_get(unsigned char *localip, unsigned char *localport,
                       unsigned char *remoteip, unsigned char *remoteport) {
    if (connectioninfo_fromenv(localip, localport, remoteip, remoteport))
        return 1;
    if (connectioninfo_fromfd(localip, localport, remoteip, remoteport))
        return 1;
    log_w1("connectioninfo_get() failed");
    return 0;
}

/*
 * connectioninfo_set - export endpoint metadata to environment variables
 *
 * @localip: 16-byte local address in normalized binary form
 * @localport: two-byte local port in network byte order
 * @remoteip: 16-byte peer address in normalized binary form
 * @remoteport: two-byte peer port in network byte order
 *
 * Converts the binary endpoint data to strings and updates the standard
 * TCPLOCAL* and TCPREMOTE* environment variables.
 */
void connectioninfo_set(unsigned char *localip, unsigned char *localport,
                        unsigned char *remoteip, unsigned char *remoteport) {
    (void) setenv("TCPREMOTEIP", iptostr(0, remoteip), 1);
    (void) setenv("TCPREMOTEPORT", porttostr(0, remoteport), 1);
    (void) setenv("TCPLOCALIP", iptostr(0, localip), 1);
    (void) setenv("TCPLOCALPORT", porttostr(0, localport), 1);
    log_t4("connectioninfo_set(): local=", log_ipport(localip, localport),
           ", remote=", log_ipport(remoteip, remoteport));
}
