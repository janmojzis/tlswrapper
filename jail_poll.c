/*
Poll() doesn't work when RLIMIT_NOFILE is set to 0;
Imitate poll() using select().
*/

#include <poll.h>
#include <sys/select.h>
#include "log.h"
#include "jail.h"


int jail_poll(struct pollfd *x, nfds_t len, int millisecs) {

    struct timeval *tvp = 0;
    struct timeval tv;
    fd_set rfds;
    fd_set wfds;
    nfds_t nfds;
    int fd, r;
    nfds_t i;

    log_t1("jail_poll()");

    for (i = 0; i < len; ++i) x[i].revents = 0;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    nfds = 1;
    for (i = 0; i < len; ++i) {
        fd = x[i].fd;
        if (fd < 0) continue;
        if (fd >= (int) (8 * sizeof(fd_set))) continue;
        if ((unsigned int) fd >= nfds) nfds = fd + 1;
        if (x[i].events & POLLIN) FD_SET(fd, &rfds);
        if (x[i].events & POLLOUT) FD_SET(fd ,&wfds);
    }

    if (millisecs >= 0) {
        tv.tv_sec = millisecs / 1000;
        tv.tv_usec = 1000 * (millisecs % 1000);
        tvp = &tv;
    }

    r = select(nfds, &rfds, &wfds, (fd_set *) 0, tvp);
    if (r <= 0) goto cleanup;

    r = 0;
    for (i = 0; i < len; ++i) {
        fd = x[i].fd;
        if (fd < 0) continue;
        if (fd >= (int) (8 * sizeof(fd_set))) continue;

        if (x[i].events & POLLIN) {
            if (FD_ISSET(fd, &rfds)) x[i].revents |= POLLIN;
            ++r;
        }
        if (x[i].events & POLLOUT) {
            if (FD_ISSET(fd, &wfds)) x[i].revents |= POLLOUT;
            ++r;
        }
    }

cleanup:
    log_t2("jail_poll() = ", lognum(r));
    return r;
}
