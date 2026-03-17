/*
 * timeoutread.c - blocking read with a deadline using select()
 *
 * Provides a timeout wrapper around read(). The implementation uses
 * select() because poll() cannot be used after RLIMIT_NOFILE is reduced
 * to zero in the jailed processes.
 */

#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include "timeoutread.h"

/*
 * timeoutread - read from a descriptor with a deadline
 *
 * @t: timeout in seconds
 * @fd: descriptor to wait on and read from
 * @buf: destination buffer
 * @len: maximum number of bytes to read
 *
 * Waits until fd becomes readable or the timeout expires, then performs a
 * single read() call.
 *
 * Constraints:
 *   - t, len, and fd must be non-negative
 *   - fd must be smaller than FD_SETSIZE
 *
 * Returns the underlying read() result, or -1 with errno set to ETIMEDOUT
 * when the deadline expires first.
 */

long long timeoutread(long long t, int fd, char *buf, long long len) {

    struct timeval tv;
    long long deadline, tm;
    fd_set rfds;

    if (t < 0 || len < 0 || fd < 0 || fd >= FD_SETSIZE) {
        errno = EINVAL;
        return -1;
    }

    gettimeofday(&tv, (struct timezone *) 0);
    deadline = 1000000LL * (t + tv.tv_sec) + tv.tv_usec;

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        gettimeofday(&tv, (struct timezone *) 0);
        tm = deadline - (1000000LL * tv.tv_sec + tv.tv_usec);
        if (tm <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (tm > 1000000000LL) tm = 1000000000LL;
        tv.tv_sec = tm / 1000000LL;
        tv.tv_usec = tm % 1000000LL;
        if (select(fd + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv) == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (FD_ISSET(fd, &rfds)) break;
    }
    return read(fd, buf, len);
}
