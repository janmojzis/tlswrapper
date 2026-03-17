/*
 * conn.c - connect to the first reachable address from a candidate list
 *
 * Provides a small parallel TCP connect helper for destination lists
 * produced by name resolution. The module opens one non-blocking socket
 * per candidate address, polls them until one connection succeeds, and
 * closes the remaining sockets.
 */

#include <unistd.h>
#include <string.h>
#include <poll.h>
#include "jail.h"
#include "socket.h"
#include "milliseconds.h"
#include "e.h"
#include "log.h"
#include "conn.h"

#define MAXIP 8

static int fds[MAXIP] = {-1, -1, -1, -1, -1, -1, -1, -1};

/*
 * conn_getip - map an internal socket slot back to its candidate address
 *
 * @fd: socket descriptor stored in the module state
 * @ip: packed array of 16-byte candidate addresses
 * @iplen: size of @ip in bytes
 *
 * Returns a pointer to the candidate address associated with @fd, or null
 * when the descriptor is not tracked.
 */
static unsigned char *conn_getip(int fd, unsigned char *ip, long long iplen) {
    long long i;
    if (iplen > MAXIP * 16) iplen = MAXIP * 16;
    for (i = 0; i < iplen / 16; ++i) {
        if (fd == fds[i]) { return ip + 16 * i; }
    }
    return 0;
}

/*
 * conn_copyip - promote the winning address and close the losing sockets
 *
 * @fd: connected socket descriptor
 * @ip: packed array of 16-byte candidate addresses
 * @iplen: size of @ip in bytes
 *
 * Copies the address associated with @fd into the first 16 bytes of @ip so
 * callers can observe which candidate succeeded. All other tracked sockets
 * are closed and removed from the module state.
 */
static void conn_copyip(int fd, unsigned char *ip, long long iplen) {
    long long i;
    if (iplen > MAXIP * 16) iplen = MAXIP * 16;

    for (i = 0; i < iplen / 16; ++i) {
        if (fd == fds[i]) { memcpy(ip, ip + 16 * i, 16); }
        else {
            if (fds[i] != -1) {
                close(fds[i]);
                fds[i] = -1;
            }
        }
    }
}

/*
 * conn_closefd - close and forget one tracked socket
 *
 * @fd: socket descriptor to close
 *
 * Closes @fd when it is present in the internal socket table and marks the
 * slot unused.
 */
static void conn_closefd(int fd) {

    long long i;

    for (i = 0; i < MAXIP; ++i) {
        if (fds[i] == -1) continue;
        if (fds[i] == fd) {
            close(fds[i]);
            fds[i] = -1;
        }
    }
}

/*
 * conn_init - create sockets for the next connection attempt
 *
 * @num: number of candidate addresses the caller plans to try
 *
 * Opens up to MAXIP TCP sockets and stores them in the module state for a
 * subsequent call to conn().
 *
 * Returns 1 on success and 0 on failure.
 */
int conn_init(long long num) {

    long long i;

    if (num > MAXIP) num = MAXIP;

    for (i = 0; i < num; ++i) {
        fds[i] = socket_tcp();
        if (fds[i] == -1) return 0;
    }
    return 1;
}

/*
 * conn - connect to the first address that succeeds before the timeout
 *
 * @timeout: connection timeout in seconds
 * @ip: packed array of 16-byte candidate addresses
 * @iplen: size of @ip in bytes
 * @port: destination port in network byte order
 *
 * Starts a non-blocking connect on each candidate address prepared by
 * conn_init(), then polls until one socket becomes connected or the timeout
 * expires. On success, the winning address is copied into the first slot
 * of @ip and the connected file descriptor is returned.
 *
 * Constraints:
 *   - @ip must contain at least one 16-byte address.
 *   - @timeout must be at least 1 second.
 *   - The caller must invoke conn_init() before calling conn().
 *
 * Returns a connected socket descriptor on success and -1 on failure.
 */
int conn(long long timeout, unsigned char *ip, long long iplen,
         unsigned char *port) {

    long long i;
    struct pollfd p[MAXIP];
    long long tm, deadline, plen;

    deadline = milliseconds() + 1000 * timeout;

    if (iplen > MAXIP * 16) iplen = MAXIP * 16;
    if (timeout < 1 || !ip || !port || iplen < 16) {
        errno = EINVAL;
        return -1;
    }

    /* Start all connects first so the fastest address wins the race. */
    for (i = 0; i < iplen / 16; ++i) {
        log_d4("sending connect to [", log_ip(ip + 16 * i),
               "]:", log_port(port));
        if (socket_connect(fds[i], ip + 16 * i, port, 0) == 0) {
            memcpy(ip, ip + 16 * i, 16);
            return fds[i];
        }
        if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
            log_w4("unable to connect to [", log_ip(ip + 16 * i),
                   "]:", log_port(port));
            close(fds[i]);
            fds[i] = -1;
        }
    }

    for (;;) {

        /* Poll only the sockets that are still in flight. */
        plen = 0;
        for (i = 0; i < iplen / 16; ++i) {
            if (fds[i] != -1) {
                p[plen].fd = fds[i];
                p[plen].events = POLLOUT;
                ++plen;
            }
        }

        if (plen == 0) return -1;

        /* Convert the absolute deadline into the next poll timeout. */
        tm = deadline - milliseconds();
        if (tm <= 0) {
            errno = ETIMEDOUT;
            for (i = 0; i < plen; ++i) {
                log_w4("unable to connect to [",
                       log_ip(conn_getip(p[i].fd, ip, iplen)),
                       "]:", log_port(port));
            }
            return -1;
        }
        jail_poll(p, plen, tm);

        /* Check completion and keep the first socket that really connected. */
        for (i = 0; i < plen; ++i) {
            if (p[i].revents) {
                if (socket_connected(p[i].fd)) {
                    conn_copyip(p[i].fd, ip, iplen);
                    errno = 0;
                    return p[i].fd;
                }
                log_w4("unable to connect to [",
                       log_ip(conn_getip(p[i].fd, ip, iplen)),
                       "]:", log_port(port));
                conn_closefd(p[i].fd);
            }
        }
    }
}
