/*
 * fd.c - file descriptor utility helpers
 *
 * This module groups small helpers for common file descriptor operations.
 * It keeps descriptor handling consistent across the codebase.
 */
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include "e.h"
#include "log.h"
#include "fd.h"

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
