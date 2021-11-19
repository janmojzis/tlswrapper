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
#include "remoteip.h"

static char buf[INET6_ADDRSTRLEN + INET_ADDRSTRLEN] = {0};

/*
The 'remoteip' returns IP address of the remote peer.
Is extracted from the getpeername() function or
from TCPREMOTEIP env. variable.
*/
const char *remoteip(void) {

    int fd = 0;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof sa;

    if (getpeername(fd, (struct sockaddr *)&sa, &salen) == 0) {

        if (sa.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
            return inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf);
        }
        if (sa.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
            return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof buf);
        }
    }
    return getenv("TCPREMOTEIP");
}
