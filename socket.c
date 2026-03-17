/*
 * socket.c - helpers for IPv6 stream sockets
 *
 * This module creates, connects, and shuts down sockets using the
 * project's IPv4-mapped IPv6 address representation.
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

/*
 * socket_tcp - create a nonblocking TCP socket
 *
 * Returns an IPv6 stream socket configured close-on-exec and, where
 * supported, able to accept IPv4-mapped peers.
 */
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

/*
 * socket_connect - start a connection to an IPv6 or mapped IPv4 peer
 *
 * @s: socket descriptor
 * @ip: 16-byte peer address
 * @port: 2-byte peer port in network byte order
 * @id: IPv6 scope identifier
 *
 * Builds a sockaddr_in6 structure from the caller-provided address parts
 * and returns the result of connect().
 */
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

/*
 * socket_connected - test whether connect() has completed
 *
 * @s: socket descriptor
 *
 * Returns 1 once a peer is attached. On failure it preserves the socket
 * error path by issuing a read() before returning 0.
 */
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

/*
 * socket_shutdown - close the local write direction
 *
 * @s: socket descriptor
 *
 * Returns shutdown(SHUT_WR) for callers that need a half-close.
 */
int socket_shutdown(int s) {
    return shutdown(s, SHUT_WR);
}
