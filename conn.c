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

static int fds[MAXIP] = { -1, -1, -1, -1, -1, -1, -1, -1 };

static unsigned char *conn_getip(int fd, unsigned char *ip, long long iplen) {
    long long i;
    if (iplen > MAXIP * 16) iplen = MAXIP * 16;
    for (i = 0; i < iplen / 16; ++i) {
        if (fd == fds[i]) {
            return ip + 16 * i;
        }
    }
    return 0;
}

static void conn_copyip(int fd, unsigned char *ip, long long iplen) {
    long long i;
    if (iplen > MAXIP * 16) iplen = MAXIP * 16;

    for (i = 0; i < iplen / 16; ++i) {
        if (fd == fds[i]) {
            memcpy(ip, ip + 16 * i, 16);
        }
        else {
            if (fds[i] != -1) {
                close(fds[i]);
                fds[i] = -1;
            }
        }
    }
}

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

int conn_init(long long num) {

    long long i;

    if (num > MAXIP) num = MAXIP;

    for (i = 0; i < MAXIP; ++i) {
        fds[i] = socket_tcp();
        if (fds[i] == -1)  return -1;
    }
    return 0;
}

int conn(long long timeout, unsigned char *ip, long long iplen, unsigned char *port) {

    long long i;
    struct pollfd p[MAXIP];
    long long tm, deadline, plen;

    deadline = milliseconds() + 1000 * timeout;

    if (iplen > MAXIP * 16) iplen = MAXIP * 16;
    if (timeout < 1 || !ip || !port || iplen < 16) {
        errno = EINVAL;
        return -1;
    }

    for (i = 0; i < iplen / 16; ++i) {
        log_d4("sending connect to [", logip(ip + 16 * i), "]:", logport(port));
        if (socket_connect(fds[i], ip + 16 * i, port, 0) == 0) {
            memcpy(ip, ip + 16 * i, 16);
            return fds[i];
        }
        if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
            log_w4("unable to connect to [", logip(ip + 16 * i), "]:", logport(port));
            close(fds[i]);
            fds[i] = -1;
        }
    }

    for (;;) {

        plen = 0;
        for (i = 0; i < iplen / 16; ++i) {
            if (fds[i] != -1) {
                p[plen].fd = fds[i];
                p[plen].events = POLLOUT;
                ++plen;
            }
        }

        if (plen == 0) return -1;

        tm = deadline - milliseconds();
        if (tm <= 0) {
            errno = ETIMEDOUT;
            for (i = 0; i < plen; ++i) {
                log_w4("unable to connect to [", logip(conn_getip(p[i].fd, ip, iplen)), "]:", logport(port));
            }
            return -1;
        }
        jail_poll(p, plen, tm);

        for (i = 0; i < plen; ++i) {
            if (p[i].revents) {
                if (socket_connected(p[i].fd)) {
                    conn_copyip(p[i].fd, ip, iplen);
                    return p[i].fd;
                }
                log_w4("unable to connect to [", logip(conn_getip(p[i].fd, ip, iplen)), "]:", logport(port));
                conn_closefd(p[i].fd);
            }

        }
    }
}
