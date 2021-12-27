/*
20131117
Jan Mojzis
Public domain.
*/

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include "blocking.h"
#include "socket.h"

int socket_tcp(void) {

    int s;
    int opt = 0;

    s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s == -1) return -1;
    if (fcntl(s, F_SETFD, 1) == -1) {
        close(s);
        return -1;
    }
#ifdef IPPROTO_IPV6
#ifdef IPV6_V6ONLY
    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof opt) == -1) {
        close(s);
        return -1;
    }
#endif
#endif
    blocking_disable(s);
    return s;
}

int socket_connect(int s, const unsigned char *ip, const unsigned char *port,
                   long long id) {

    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    memcpy(&sa.sin6_addr, ip, 16);
    memcpy(&sa.sin6_port, port, 2);
    sa.sin6_scope_id = id;
    return connect(s, (struct sockaddr *) &sa, sizeof sa);
}

int socket_connected(int s) {

    struct sockaddr sa;
    socklen_t dummy;
    char ch;

    dummy = sizeof sa;
    if (getpeername(s, &sa, &dummy) == -1) {
        if (read(s, &ch, 1) == -1) { /* sets errno */
        };
        return 0;
    }
    return 1;
}
