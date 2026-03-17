/*
 * blocking.c - toggle blocking mode on file descriptors
 *
 * This module provides small helpers that centralize how the codebase
 * enables or disables O_NONBLOCK on an existing descriptor.
 */

#include <fcntl.h>
#include "blocking.h"

/*
 * blocking_enable - switch a descriptor to blocking mode
 *
 * @fd: descriptor to reconfigure
 *
 * Clears O_NONBLOCK on @fd. Errors are left to fcntl().
 */
void blocking_enable(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
}

/*
 * blocking_disable - switch a descriptor to nonblocking mode
 *
 * @fd: descriptor to reconfigure
 *
 * Sets O_NONBLOCK on @fd. Errors are left to fcntl().
 */
void blocking_disable(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}
