/*
20211119
Jan Mojzis
Public domain.
*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "strtoip.h"
#include "strtoport.h"
#include "connectioninfo.h"


/*
The connectioninfo_fromfd function gets
informations about TCP connection from the
getsockname(), getpeername() libc functions.
*/
static int connectioninfo_fromfd(unsigned char *localip, unsigned char *localport, unsigned char *remoteip, unsigned char *remoteport) {

    int fd = 0;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof sa;

    /* local ip */
    if (getsockname(fd, (struct sockaddr *)&sa, &salen) == -1) return 0;

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
        memcpy(localip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
        memcpy(localip + 12, &sin->sin_addr, 4);
        memcpy(localport, &sin->sin_port, 2);
    }
    if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
        memcpy(localip, &sin6->sin6_addr, 16);
        memcpy(localport, &sin6->sin6_port, 2);
    }

    /* remote ip */
    if (getpeername(fd, (struct sockaddr *)&sa, &salen) == -1) return 0;

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
        memcpy(remoteip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
        memcpy(remoteip + 12, &sin->sin_addr, 4);
        memcpy(remoteport, &sin->sin_port, 2);
    }
    if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
        memcpy(remoteip, &sin6->sin6_addr, 16);
        memcpy(remoteport, &sin6->sin6_port, 2);
    }

    return 1;
}

/*
The connectioninfo_fromenv function gets
informations about TCP connection from the environment.
*/
static int connectioninfo_fromenv(unsigned char *localip, unsigned char *localport, unsigned char *remoteip, unsigned char *remoteport) {

    if (!strtoip(localip, getenv("TCPLOCALIP"))) return 0;
    if (!strtoport(localport, getenv("TCPLOCALPORT"))) return 0;
    if (!strtoip(remoteip, getenv("TCPREMOTEIP"))) return 0;
    if (!strtoport(remoteport, getenv("TCPREMOTEPORT"))) return 0;
    return 1;
}

int connectioninfo(unsigned char *localip, unsigned char *localport, unsigned char *remoteip, unsigned char *remoteport) {
    if (connectioninfo_fromenv(localip, localport, remoteip, remoteport)) return 1;
    if (connectioninfo_fromfd(localip, localport, remoteip, remoteport)) return 1;
    return 0;
}
