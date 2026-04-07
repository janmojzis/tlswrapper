/*
 * conn.c - connect to the first reachable address from a candidate list
 *
 * Provides a small parallel TCP connect helper for destination lists
 * produced by name resolution. The module keeps process-global state,
 * opens one non-blocking socket plus one duplicate descriptor per
 * candidate address, polls until one connection succeeds or all
 * candidates fail, and closes the remaining sockets.
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
static int dupfds[MAXIP] = {-1, -1, -1, -1, -1, -1, -1, -1};

/*
 * conn_findslot - locate the tracked slot that owns a descriptor
 *
 * @fd: socket descriptor stored in the module state
 *
 * Returns the slot index for @fd, or -1 when the descriptor is not tracked.
 */
static long long conn_findslot(int fd) {
    long long i;

    for (i = 0; i < MAXIP; ++i) {
        if (fds[i] == fd) return i;
    }
    return -1;
}

/*
 * conn_closeslot - close all tracked descriptors for one slot
 *
 * @slot: slot index in the module state
 *
 * Closes both the primary socket and its duplicate descriptor for @slot and
 * marks the slot unused. Invalid slot indices are ignored.
 */
static void conn_closeslot(long long slot) {
    int saved_errno;

    if (slot < 0 || slot >= MAXIP) return;

    log_t6("conn_closeslot slot=", log_num(slot), " fd=", log_num(fds[slot]),
           " dupfd=", log_num(dupfds[slot]));

    saved_errno = errno;
    close(fds[slot]);
    close(dupfds[slot]);
    errno = saved_errno;

    fds[slot] = -1;
    dupfds[slot] = -1;
}

/*
 * conn_reset - close all tracked descriptors prepared by conn_init()
 *
 * Closes both the primary socket and its duplicate descriptor for every
 * tracked slot and marks the slot unused.
 */
static void conn_reset(void) {
    long long i;
    for (i = 0; i < MAXIP; ++i) { conn_closeslot(i); }
}

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
    long long slot;
    if (iplen > MAXIP * 16) iplen = MAXIP * 16;
    slot = conn_findslot(fd);
    if (slot < 0 || slot >= iplen / 16) return 0;
    return ip + 16 * slot;
}

/*
 * conn_copyip - promote the winning address and close the losing sockets
 *
 * @fd: connected socket descriptor
 * @ip: packed array of 16-byte candidate addresses
 * @iplen: size of @ip in bytes
 * @dupfd: receives the duplicate descriptor for the winning socket
 *
 * Copies the address associated with @fd into the first 16 bytes of @ip so
 * callers can observe which candidate succeeded. The winning slot keeps its
 * original descriptor in @fd and returns its duplicate through @dupfd; all
 * other tracked descriptors are closed and removed from the module state.
 */
static void conn_copyip(int fd, unsigned char *ip, long long iplen,
                        int *dupfd) {
    long long i, slot;
    if (iplen > MAXIP * 16) iplen = MAXIP * 16;
    if (dupfd) *dupfd = -1;
    slot = conn_findslot(fd);
    if (slot < 0 || slot >= iplen / 16) return;

    for (i = 0; i < iplen / 16; ++i) {
        if (i == slot) {
            log_t8("conn winner slot ", log_num(i), " fd=", log_num(fds[i]),
                   " dupfd=", log_num(dupfds[i]),
                   " peer=", log_ip(ip + 16 * i));
            memmove(ip, ip + 16 * i, 16);
            if (dupfd) *dupfd = dupfds[i];
            dupfds[i] = -1;
            fds[i] = -1;
        }
        else {
            if (fds[i] != -1 || dupfds[i] != -1) conn_closeslot(i);
        }
    }
}

/*
 * conn_closefd - close and forget one tracked socket
 *
 * @fd: socket descriptor to close
 *
 * Closes @fd when it is present in the internal socket table, also closes
 * the matching duplicate descriptor for that candidate, and marks the slot
 * unused.
 */
static void conn_closefd(int fd) { conn_closeslot(conn_findslot(fd)); }

/*
 * conn_init - create sockets for the next connection attempt
 *
 * @num: number of candidate addresses the caller plans to try
 *
 * Opens up to MAXIP TCP sockets, duplicates each descriptor, and stores the
 * pairs in process-global module state for a subsequent call to conn().
 * Repeated calls discard any still-tracked descriptors from a previous
 * attempt.
 *
 * Returns 1 on success and 0 on failure.
 */
int conn_init(long long num) {

    long long i;

    conn_reset();
    if (num > MAXIP) num = MAXIP;
    log_t4("conn_init requested candidates=", log_num(num),
           ", max=", log_num(MAXIP));

    for (i = 0; i < num; ++i) {
        fds[i] = socket_tcp();
        if (fds[i] == -1) {
            conn_reset();
            return 0;
        }
        dupfds[i] = dup(fds[i]);
        if (dupfds[i] == -1) {
            conn_reset();
            return 0;
        }
        log_t6("prepared slot ", log_num(i), " fd=", log_num(fds[i]),
               " dupfd=", log_num(dupfds[i]));
    }
    return 1;
}

/*
 * conn - connect and return both prepared descriptors for the winner
 *
 * @connfds: receives the connected descriptor pair
 * @timeout: connection timeout in seconds
 * @ip: packed array of 16-byte candidate addresses
 * @iplen: size of @ip in bytes
 * @port: destination port in network byte order
 *
 * Starts a non-blocking connect on each candidate address prepared by
 * conn_init(), then polls until one socket becomes connected, all
 * candidates have failed, or the timeout expires. On success, the winning
 * address is copied into the first slot of @ip and both prepared
 * descriptors are returned to the caller.
 *
 * Constraints:
 *   - @ip must contain at least one 16-byte address.
 *   - @timeout must be at least 1 second.
 *   - The caller must invoke conn_init() before calling conn().
 *   - conn_init() must have prepared at least iplen / 16 candidate slots.
 *   - The module is not reentrant; concurrent attempts share global state.
 *
 * Returns 1 on success and 0 on failure.
 */
int conn(int connfds[2], long long timeout, unsigned char *ip, long long iplen,
         unsigned char *port) {

    long long i;
    struct pollfd p[MAXIP];
    long long tm, deadline, plen;
    int fd, dupfd;

    deadline = milliseconds() + 1000 * timeout;
    if (connfds) {
        connfds[0] = -1;
        connfds[1] = -1;
    }

    if (iplen > MAXIP * 16) iplen = MAXIP * 16;
    if (timeout < 1 || !ip || !port || iplen < 16 || !connfds) {
        errno = EINVAL;
        return 0;
    }
    log_t9("conn(timeout=", log_num(timeout), ", iplen=", log_num(iplen),
           ", candidates=", log_num(iplen / 16), ", port=", log_port(port),
           ")");

    /* Start non-blocking connects; return immediately if one succeeds
     * synchronously, otherwise let the remaining candidates race. */
    for (i = 0; i < iplen / 16; ++i) {
        log_t2("sending connect to ", log_ipport(ip + 16 * i, port));
        if (socket_connect(fds[i], ip + 16 * i, port, 0) == 0) {
            log_d2("connected to ", log_ipport(ip + 16 * i, port));
            fd = fds[i];
            conn_copyip(fd, ip, iplen, &dupfd);
            connfds[0] = fd;
            connfds[1] = dupfd;
            errno = 0;
            return 1;
        }
        if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
            log_t2("connect in progress for ", log_ipport(ip + 16 * i, port));
        }
        if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
            log_w2("unable to connect to ", log_ipport(ip + 16 * i, port));
            log_t3("connect failed immediately with ", e_str(errno), "");
            conn_closeslot(i);
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

        if (plen == 0) {
            log_t1("all connect candidates failed before timeout");
            conn_reset();
            return 0;
        }

        /* Convert the absolute deadline into the next poll timeout. */
        tm = deadline - milliseconds();
        if (tm <= 0) {
            errno = ETIMEDOUT;
            log_t4("connect timeout expired, pending=", log_num(plen),
                   ", deadline_ms=", log_num(deadline));
            for (i = 0; i < plen; ++i) {
                log_w2("unable to connect to ",
                       log_ipport(conn_getip(p[i].fd, ip, iplen), port));
            }
            conn_reset();
            return 0;
        }
        log_t4("polling pending connects, count=", log_num(plen),
               ", timeout_ms=", log_num(tm));
        if (jail_poll(p, plen, tm) == -1) {
            if (errno == EINTR) {
                log_t1("jail_poll interrupted by signal, retrying");
                continue;
            }
            log_t3("jail_poll failed with ", e_str(errno), "");
            conn_reset();
            return 0;
        }

        /* Check completion and keep the first socket that really connected. */
        for (i = 0; i < plen; ++i) {
            if (p[i].revents) {
                log_t6("poll event fd=", log_num(p[i].fd),
                       " revents=", log_num(p[i].revents), " peer=",
                       log_ipport(conn_getip(p[i].fd, ip, iplen), port));
                if (socket_connected(p[i].fd)) {
                    log_d2("connected to ",
                           log_ipport(conn_getip(p[i].fd, ip, iplen), port));
                    fd = p[i].fd;
                    conn_copyip(fd, ip, iplen, &dupfd);
                    connfds[0] = fd;
                    connfds[1] = dupfd;
                    errno = 0;
                    return 1;
                }
                log_w2("unable to connect to ",
                       log_ipport(conn_getip(p[i].fd, ip, iplen), port));
                conn_closefd(p[i].fd);
            }
        }
    }
}
