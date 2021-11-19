/*
20201103
Jan Mojzis
Public domain.
*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "porttostr.h"
#include "log.h"
#include "connectioninfo.h"

static char buf[INET6_ADDRSTRLEN + INET_ADDRSTRLEN];
static char portbuf[PORTTOSTR_LEN];

const char *connectioninfo(void) {

    int fd = 0;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof sa;

    /* local ip */
    if (getsockname(fd, (struct sockaddr *)&sa, &salen) == 0) {

        if (sa.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf);
            porttostr(portbuf, (unsigned char *)&sin->sin_port);
            setenv("TLSWRAPPER_LOCALIP", buf, 1);
            setenv("TLSWRAPPER_LOCALPORT", portbuf, 1);
        }
        if (sa.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
            inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof buf);
            porttostr(portbuf, (unsigned char *)&sin6->sin6_port);
            setenv("TLSWRAPPER_LOCALIP", buf, 1);
            setenv("TLSWRAPPER_LOCALPORT", portbuf, 1);
        }
    }

    /* remote ip */
    if (getpeername(fd, (struct sockaddr *)&sa, &salen) == 0) {

        if (sa.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf);
            porttostr(portbuf, (unsigned char *)&sin->sin_port);
            setenv("TLSWRAPPER_PROTO", "TCP4", 1);
            setenv("TLSWRAPPER_REMOTEIP", buf, 1);
            setenv("TLSWRAPPER_REMOTEPORT", portbuf, 1);
        }
        if (sa.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
            inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof buf);
            porttostr(portbuf, (unsigned char *)&sin6->sin6_port);
            setenv("TLSWRAPPER_PROTO", "TCP6", 1);
            setenv("TLSWRAPPER_REMOTEIP", buf, 1);
            setenv("TLSWRAPPER_REMOTEPORT", "0", 1);
        }
    }

    return buf;
}
