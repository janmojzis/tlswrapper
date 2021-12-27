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
#include "porttostr.h"
#include "iptostr.h"
#include "log.h"
#include "connectioninfo.h"

/*
The connectioninfo_fromfd function gets
informations about TCP connection from the
getsockname(), getpeername() libc functions.
Also sets env. variables TCPREMOTEIP, TCPREMOTEPORT,
TCPLOCALIP, TCPLOCALPORT.
*/
static int connectioninfo_fromfd(unsigned char *localip,
                                 unsigned char *localport,
                                 unsigned char *remoteip,
                                 unsigned char *remoteport) {

    int fd = 0;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof sa;

    /* local ip */
    if (getsockname(fd, (struct sockaddr *) &sa, &salen) == -1) return 0;

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &sa;
        memcpy(localip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
        memcpy(localip + 12, &sin->sin_addr, 4);
        memcpy(localport, &sin->sin_port, 2);
    }
    if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sa;
        memcpy(localip, &sin6->sin6_addr, 16);
        memcpy(localport, &sin6->sin6_port, 2);
    }

    /* remote ip */
    if (getpeername(fd, (struct sockaddr *) &sa, &salen) == -1) return 0;

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &sa;
        memcpy(remoteip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
        memcpy(remoteip + 12, &sin->sin_addr, 4);
        memcpy(remoteport, &sin->sin_port, 2);
    }
    if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sa;
        memcpy(remoteip, &sin6->sin6_addr, 16);
        memcpy(remoteport, &sin6->sin6_port, 2);
    }
    log_t8("connectioninfo_fromfd(): localip=", logip(localip),
           ", localport=", logport(localport), ", remote=", logip(remoteip),
           ", remoteport=", logport(remoteport));
    return 1;
}

/*
The connectioninfo_fromenv function gets
informations about TCP connection from the environment.
*/
static int connectioninfo_fromenv(unsigned char *localip,
                                  unsigned char *localport,
                                  unsigned char *remoteip,
                                  unsigned char *remoteport) {

    if (!strtoip(localip, getenv("TCPLOCALIP"))) return 0;
    if (!strtoport(localport, getenv("TCPLOCALPORT"))) return 0;
    if (!strtoip(remoteip, getenv("TCPREMOTEIP"))) return 0;
    if (!strtoport(remoteport, getenv("TCPREMOTEPORT"))) return 0;
    log_t8("connectioninfo_fromenv(): localip=", logip(localip),
           ", localport=", logport(localport), ", remote=", logip(remoteip),
           ", remoteport=", logport(remoteport));
    return 1;
}

int connectioninfo_get(unsigned char *localip, unsigned char *localport,
                       unsigned char *remoteip, unsigned char *remoteport) {
    if (connectioninfo_fromenv(localip, localport, remoteip, remoteport))
        return 1;
    if (connectioninfo_fromfd(localip, localport, remoteip, remoteport))
        return 1;
    log_w1("connectioninfo_get() failed");
    return 0;
}

void connectioninfo_set(unsigned char *localip, unsigned char *localport,
                        unsigned char *remoteip, unsigned char *remoteport) {
    (void) setenv("TCPREMOTEIP", iptostr(0, remoteip), 1);
    (void) setenv("TCPREMOTEPORT", porttostr(0, remoteport), 1);
    (void) setenv("TCPLOCALIP", iptostr(0, localip), 1);
    (void) setenv("TCPLOCALPORT", porttostr(0, localport), 1);
    log_t8("connectioninfo_set(): localip=", logip(localip),
           ", localport=", logport(localport), ", remote=", logip(remoteip),
           ", remoteport=", logport(remoteport));
}
