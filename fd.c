/*
 * fd.c - file descriptor utility helpers
 *
 * This module introduces a small abstraction around file descriptors.
 * It handles the tricky close semantics of the read and write ends of
 * sockets, pipes, and similar objects.
 *
 * It also provides small helpers for configuring descriptor flags and
 * related parameters, such as O_NONBLOCK and FD_CLOEXEC.
 */
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include "log.h"
#include "fd.h"

/*
 * fd_read_ - read from a descriptor using long long lengths
 *
 * @fd: descriptor to read from
 * @buf: destination buffer
 * @len: maximum number of bytes to read
 *
 * Performs a single read() call without logging. Negative lengths are
 * rejected with EINVAL. Lengths above 1 MiB are capped to 1 MiB before
 * calling read(). On failure, EWOULDBLOCK is normalized to EAGAIN.
 */
long long fd_read_(int fd, void *buf, long long len) {
    long long r = -1;

    if (!buf) goto err;
    if (len < 0) goto err;

    errno = 0;
    r = (long long) read(fd, buf, (size_t) (len > 1048576 ? 1048576 : len));
    if (r == -1 && errno == EWOULDBLOCK) errno = EAGAIN;
    return r;

err:
    errno = EINVAL;
    return -1;
}

/*
 * fd_read - read from a descriptor using long long lengths with logging
 *
 * @fdname: descriptor name used in tracing logs
 * @fd: descriptor to read from
 * @buf: destination buffer
 * @len: maximum number of bytes to read
 *
 * Rejects invalid buffer and length arguments before I/O. When @fdname is
 * NULL, performs the read without logging. Otherwise delegates I/O to
 * fd_read_() and emits the call result through the tracing log.
 */
long long fd_read(const char *fdname, int fd, void *buf, long long len) {
    long long r = -1;

    if (!buf) {
        errno = EINVAL;
        log_b1("fd_read() called with buf = (null)");
        return -1;
    }
    if (len < 0) {
        errno = EINVAL;
        log_b2("fd_read() called with len = ", log_num(len));
        return -1;
    }

    r = fd_read_(fd, buf, len);
    if (!fdname) return r;
    if (r == -1) {
        log_t8("fd_read(", log_str(fdname), ", ", log_num(len),
               ") = ", log_num(r), ", errno = ", log_errno(errno));
    }
    else {
        log_t6("fd_read(", log_str(fdname), ", ", log_num(len),
               ") = ", log_num(r));
    }
    return r;
}

/*
 * fd_write_ - write to a descriptor using long long lengths
 *
 * @fd: descriptor to write to
 * @buf: source buffer
 * @len: maximum number of bytes to write
 *
 * Performs a single write() call without logging. Negative lengths are
 * rejected with EINVAL. Lengths above 1 MiB are capped to 1 MiB before
 * calling write(). On failure, EWOULDBLOCK is normalized to EAGAIN.
 */
long long fd_write_(int fd, const void *buf, long long len) {
    long long r = -1;

    if (!buf) goto err;
    if (len < 0) goto err;

    errno = 0;
    r = (long long) write(fd, buf, (size_t) (len > 1048576 ? 1048576 : len));
    if (r == -1 && errno == EWOULDBLOCK) errno = EAGAIN;
    return r;

err:
    errno = EINVAL;
    return -1;
}

/*
 * fd_write - write to a descriptor using long long lengths with logging
 *
 * @fdname: descriptor name used in tracing logs
 * @fd: descriptor to write to
 * @buf: source buffer
 * @len: maximum number of bytes to write
 *
 * Rejects invalid buffer and length arguments before I/O. When @fdname is
 * NULL, performs the write without logging. Otherwise delegates I/O to
 * fd_write_() and emits the call result through the tracing log.
 */
long long fd_write(const char *fdname, int fd, const void *buf, long long len) {
    long long r = -1;

    if (!buf) {
        errno = EINVAL;
        log_b1("fd_write() called with buf = (null)");
        return -1;
    }
    if (len < 0) {
        errno = EINVAL;
        log_b2("fd_write() called with len = ", log_num(len));
        return -1;
    }

    r = fd_write_(fd, buf, len);
    if (!fdname) return r;
    if (r == -1) {
        log_t8("fd_write(", log_str(fdname), ", ", log_num(len),
               ") = ", log_num(r), ", errno = ", log_errno(errno));
    }
    else {
        log_t6("fd_write(", log_str(fdname), ", ", log_num(len),
               ") = ", log_num(r));
    }
    return r;
}

/*
 * tryshutdown - attempt a socket shutdown while ignoring expected failures
 *
 * @fd: descriptor to shut down
 * @how: shutdown direction passed to shutdown()
 * @who: caller name used in the warning message
 *
 * Suppresses errors for descriptors that are already invalid, disconnected,
 * or not sockets. Unexpected failures are reported through the logging layer.
 *
 * Returns 1 when shutdown() succeeded and 0 otherwise.
 */
static int tryshutdown(int fd, int how, const char *who) {
    if (shutdown(fd, how) == 0) return 1;
    if (errno == ENOTCONN || errno == EBADF || errno == ENOTSOCK ||
        errno == EINVAL) {
        return 0;
    }
    log_w2("shutdown() failed during ", who);
    return 0;
}

/*
 * tryclose - attempt a close while reporting unexpected failures
 *
 * @fd: descriptor to close
 * @who: caller name used in the warning message
 *
 * Returns 1 when close() succeeded and 0 otherwise.
 */
static int tryclose(int fd, const char *who) {
    if (close(fd) == 0) return 1;
    if (errno != EBADF) { log_w2("close() failed during ", who); }
    return 0;
}

/*
 * fd_close_read - close a tracked read descriptor and mark it inactive
 *
 * @fdname: descriptor name used in tracing logs
 * @fd: descriptor slot to close
 *
 * Attempts SHUT_RD on the current descriptor and then closes it. If @fd is
 * already inactive, the function returns without changing errno.
 *
 * Constraints:
 *   - For a full-duplex socket, independent later calls to fd_close_read()
 *     and fd_close_write() require separate duplicated descriptors, typically
 *     created with dup().
 */
void fd_close_read(const char *fdname, int *fd) {
    int saved_errno = errno;
    const char *shutdownstr = "";
    const char *closestr = "";

    if (!fdname) {
        errno = EINVAL;
        log_b1("fd_close_read() called with fdname = (null)");
        return;
    }
    if (!fd) {
        errno = EINVAL;
        log_b1("fd_close_read() called with fd = (null)");
        return;
    }
    if (*fd == -1) return;

    if (tryshutdown(*fd, SHUT_RD, "fd_close_read")) {
        shutdownstr = "shutdown,";
    }
    if (tryclose(*fd, "fd_close_read")) { closestr = "close,"; }
    log_t5("fd_close_read(", log_str(fdname), ") = ", shutdownstr, closestr);
    *fd = -1;
    errno = saved_errno;
}

/*
 * fd_close_write - close a tracked write descriptor and mark it inactive
 *
 * @fdname: descriptor name used in tracing logs
 * @fd: descriptor slot to close
 *
 * Attempts SHUT_WR on the current descriptor and then closes it. If @fd is
 * already inactive, the function returns without changing errno.
 *
 * Constraints:
 *   - For a full-duplex socket, independent later calls to fd_close_read()
 *     and fd_close_write() require separate duplicated descriptors, typically
 *     created with dup().
 */
void fd_close_write(const char *fdname, int *fd) {
    int saved_errno = errno;
    const char *shutdownstr = "";
    const char *closestr = "";

    if (!fdname) {
        errno = EINVAL;
        log_b1("fd_close_write() called with fdname = (null)");
        return;
    }
    if (!fd) {
        errno = EINVAL;
        log_b1("fd_close_write() called with fd = (null)");
        return;
    }
    if (*fd == -1) return;

    if (tryshutdown(*fd, SHUT_WR, "fd_close_write")) {
        shutdownstr = "shutdown,";
    }
    if (tryclose(*fd, "fd_close_write")) { closestr = "close,"; }
    log_t5("fd_close_write(", log_str(fdname), ") = ", shutdownstr, closestr);
    *fd = -1;
    errno = saved_errno;
}

/*
 * fd_blocking_enable - switch a descriptor to blocking mode
 *
 * @fd: descriptor to reconfigure
 *
 * Clears O_NONBLOCK on @fd.
 */
void fd_blocking_enable(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1) {
        log_w1("fcntl(F_GETFL) failed during fd_blocking_enable");
        return;
    }
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

/*
 * fd_blocking_disable - switch a descriptor to nonblocking mode
 *
 * @fd: descriptor to reconfigure
 *
 * Sets O_NONBLOCK on @fd.
 */
void fd_blocking_disable(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1) {
        log_w1("fcntl(F_GETFL) failed during fd_blocking_disable");
        return;
    }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/*
 * fd_coe_enable - enable close-on-exec on a descriptor
 *
 * @fd: descriptor to reconfigure
 *
 * Set FD_CLOEXEC on @fd.
 */
void fd_coe_enable(int fd) {
    int flags = fcntl(fd, F_GETFD, 0);

    if (flags == -1) {
        log_w1("fcntl(F_GETFD) failed during fd_coe_enable");
        return;
    }
    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

/*
 * fd_coe_disable - disable close-on-exec on a descriptor
 *
 * @fd: descriptor to reconfigure
 *
 * Clears FD_CLOEXEC on @fd.
 */
void fd_coe_disable(int fd) {
    int flags = fcntl(fd, F_GETFD, 0);

    if (flags == -1) {
        log_w1("fcntl(F_GETFD) failed during fd_coe_disable");
        return;
    }
    fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
}
