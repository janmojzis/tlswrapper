/*
 * jail_poll.c - poll-like waiting that survives RLIMIT_NOFILE == 0
 *
 * Provides a small compatibility wrapper used inside jailed processes.
 * When RLIMIT_NOFILE is forced to zero, poll() may stop working on some
 * platforms, so this module emulates the needed POLLIN/POLLOUT subset
 * with select().
 *
 * The behavior is intentionally narrow and does not match poll() in every
 * edge case. In particular, EBADF handling may differ.
 */

#include <poll.h>
#include <sys/select.h>
#include <errno.h>
#include "log.h"
#include "jail.h"

/*
 * jail_poll - wait for readable or writable descriptors with select()
 *
 * @x: pollfd-style descriptor array
 * @len: number of entries in @x
 * @millisecs: timeout in milliseconds, or negative for no timeout
 *
 * Clears all revents fields, translates requested POLLIN/POLLOUT events
 * into fd_sets, and waits with select(). On return, the function writes
 * back the corresponding POLLIN/POLLOUT readiness bits into @x.
 *
 * Constraints:
 *   - Only POLLIN and POLLOUT are observed.
 *   - All non-negative descriptors must be smaller than FD_SETSIZE.
 *
 * Returns the number of reported readiness flags, 0 on timeout, and -1 on
 * error.
 */
int jail_poll(struct pollfd *x, nfds_t len, int millisecs) {

    struct timeval *tvp = 0;
    struct timeval tv;
    fd_set rfds;
    fd_set wfds;
    nfds_t nfds;
    int fd, r = -1;
    nfds_t i;

    log_t5("jail_poll(len = ", log_num(len),
           ", millisecs = ", log_num(millisecs), ")");

    for (i = 0; i < len; ++i) x[i].revents = 0;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    nfds = 1;
    for (i = 0; i < len; ++i) {
        fd = x[i].fd;
        if (fd < 0) continue;
        if (fd >= FD_SETSIZE) {
            errno = EINVAL;
            log_e3("fd ", log_num(fd), " exceeds FD_SETSIZE");
            goto cleanup;
        }
        if ((unsigned int) fd >= nfds) nfds = fd + 1;
        if (x[i].events & POLLIN) FD_SET(fd, &rfds);
        if (x[i].events & POLLOUT) FD_SET(fd, &wfds);
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
        if (fd >= FD_SETSIZE) {
            errno = EINVAL;
            log_e3("fd ", log_num(fd), " exceeds FD_SETSIZE");
            r = -1;
            goto cleanup;
        }

        if (x[i].events & POLLIN) {
            if (FD_ISSET(fd, &rfds)) {
                x[i].revents |= POLLIN;
                ++r;
            }
        }
        if (x[i].events & POLLOUT) {
            if (FD_ISSET(fd, &wfds)) {
                x[i].revents |= POLLOUT;
                ++r;
            }
        }
    }

cleanup:
    log_t6("jail_poll(len = ", log_num(len),
           ", millisecs = ", log_num(millisecs), ") = ", log_num(r));
    return r;
}
