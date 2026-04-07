/*
 * fd.c - uniform close helpers for read and write descriptors
 *
 * This module provides a small abstraction over descriptors that are tracked
 * only by direction: a descriptor is either the one we read from or the one
 * we write to.
 *
 * Callers do not need to care whether the descriptor is a pipe end, a
 * duplicated socket, a regular file, or some other fd type. They only decide
 * whether reads or writes are no longer needed:
 *
 * - fd_close_read() is used when no more reads are needed.
 * - fd_close_write() is used when no more writes are needed.
 *
 * The helper then applies the appropriate low-level operation:
 *
 * - shutdown() is attempted in the matching direction (harmless on non-sockets)
 * - then the descriptor is closed
 *
 * This keeps call sites uniform across independent descriptor pairs,
 * duplicated sockets, and other mixed fd setups: once reads are no longer
 * needed call fd_close_read(), and once writes are no longer needed call
 * fd_close_write().
 *
 * Warning: for a full-duplex socket, separate calls to fd_close_read() and
 * fd_close_write() only make sense when the socket is tracked through
 * separate file descriptors, typically created with dup(). Calling both
 * helpers on the same socket fd will close that fd on the first call, so the
 * second call cannot perform a later directional shutdown.
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
 * Clears O_NONBLOCK on @fd. Errors are left to fcntl().
 */
void fd_blocking_enable(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
}

/*
 * fd_blocking_disable - switch a descriptor to nonblocking mode
 *
 * @fd: descriptor to reconfigure
 *
 * Sets O_NONBLOCK on @fd. Errors are left to fcntl().
 */
void fd_blocking_disable(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}
