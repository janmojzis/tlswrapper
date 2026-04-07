/*
 * open_pipe.c - create close-on-exec nonblocking pipes
 *
 * This module wraps pipe creation so both ends are configured the same
 * way throughout the codebase.
 */

#include <unistd.h>
#include <fcntl.h>
#include "open.h"
#include "fd.h"

/*
 * open_pipe - create a pipe and prepare both descriptors
 *
 * @fd: two-element descriptor array filled by pipe()
 *
 * Returns 0 on success. Both ends are marked close-on-exec and switched
 * to nonblocking mode before the function returns.
 */
int open_pipe(int *fd) {
    int i;
    if (pipe(fd) == -1) return -1;
    for (i = 0; i < 2; ++i) {
        fcntl(fd[i], F_SETFD, 1);
        fd_blocking_disable(fd[i]);
    }
    return 0;
}
