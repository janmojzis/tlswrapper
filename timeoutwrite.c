/*
 * timeoutwrite.c - blocking write with a deadline using select()
 *
 * Provides a timeout wrapper around write(). The implementation uses
 * select() because poll() cannot be used after RLIMIT_NOFILE is reduced
 * to zero in the jailed processes.
 */

#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include "timeoutwrite.h"

/*
 * timeoutwrite - write to a descriptor with a deadline
 *
 * @t: timeout in seconds
 * @fd: descriptor to wait on and write to
 * @buf: source buffer
 * @len: maximum number of bytes to write
 *
 * Waits until fd becomes writable or the timeout expires, then performs a
 * single write() call.
 *
 * Constraints:
 *   - t, len, and fd must be non-negative
 *   - fd must be smaller than FD_SETSIZE
 *
 * Returns the underlying write() result, or -1 with errno set to ETIMEDOUT
 * when the deadline expires first.
 */

long long timeoutwrite(long long t, int fd, const char *buf, long long len) {

    struct timeval tv;
    long long deadline, tm;
    fd_set wfds;

    if (t < 0 || len < 0 || fd < 0 || fd >= FD_SETSIZE) {
        errno = EINVAL;
        return -1;
    }

    gettimeofday(&tv, (struct timezone *) 0);
    deadline = 1000000LL * (t + tv.tv_sec) + tv.tv_usec;

    for (;;) {
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);

        gettimeofday(&tv, (struct timezone *) 0);
        tm = deadline - (1000000LL * tv.tv_sec + tv.tv_usec);
        if (tm <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (tm > 1000000000LL) tm = 1000000000LL;
        tv.tv_sec = tm / 1000000LL;
        tv.tv_usec = tm % 1000000LL;
        if (select(fd + 1, (fd_set *) 0, &wfds, (fd_set *) 0, &tv) == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (FD_ISSET(fd, &wfds)) break;
    }
    return write(fd, buf, (size_t) len);
}
