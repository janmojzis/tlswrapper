/*
 * fd.c - file descriptor utility helpers
 *
 * This module introduces a small abstraction around file descriptors.
 * It handles the tricky close semantics of the read and write ends of
 * sockets, pipes, and similar objects.
 * It also provides small helpers for configuring descriptor flags and
 * related parameters, such as O_NONBLOCK and FD_CLOEXEC.
 */
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include "e.h"
#include "log.h"
#include "fd.h"

/*
 * tryshutdown - attempt a socket shutdown while ignoring expected failures
 *
 * @fd: descriptor to shut down
 * @how: shutdown direction passed to shutdown()
 * @who: caller name used in the warning message
 *
 * Suppresses errors for descriptors that are already invalid, disconnected,
 * or not sockets. Unexpected failures are reported through the logging layer.
 */
static void tryshutdown(int fd, int how, const char *who) {
    if (shutdown(fd, how) == -1) {
        if (errno != ENOTCONN && errno != EBADF && errno != ENOTSOCK &&
            errno != EINVAL) {
            log_w2("shutdown() failed during ", who);
        }
    }
}

/*
 * fd_close_read - close a tracked read descriptor and mark it inactive
 *
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
void fd_close_read(int *fd) {
    int saved_errno = errno;
    if (*fd == -1) return;
    tryshutdown(*fd, SHUT_RD, "fd_close_read");
    close(*fd);
    *fd = -1;
    errno = saved_errno;
}

/*
 * fd_close_write - close a tracked write descriptor and mark it inactive
 *
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
void fd_close_write(int *fd) {
    int saved_errno = errno;
    if (*fd == -1) return;
    tryshutdown(*fd, SHUT_WR, "fd_close_write");
    close(*fd);
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
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
}

/*
 * fd_blocking_disable - switch a descriptor to nonblocking mode
 *
 * @fd: descriptor to reconfigure
 *
 * Sets O_NONBLOCK on @fd.
 */
void fd_blocking_disable(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

/*
 * fd_coe_enable - enable close-on-exec on a descriptor
 *
 * @fd: descriptor to reconfigure
 *
 * Set FD_CLOEXEC on @fd.
 */
void fd_coe_enable(int fd) {
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
}

/*
 * fd_coe_disable - disable close-on-exec on a descriptor
 *
 * @fd: descriptor to reconfigure
 *
 * Clears FD_CLOEXEC on @fd.
 */
void fd_coe_disable(int fd) {
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) & ~FD_CLOEXEC);
}
