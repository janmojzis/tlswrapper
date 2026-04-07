/*
 * open_read.c - open input files for read
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "open.h"

/*
 * open_read - open a file read-only with close-on-exec semantics
 *
 * @fn: path to open
 *
 * Returns a descriptor opened with O_NONBLOCK or -1 on failure. When
 * O_CLOEXEC is unavailable, the function applies FD_CLOEXEC after open().
 */
int open_read(const char *fn) {
#ifdef O_CLOEXEC
    return open(fn, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
#else
    int fd = open(fn, O_RDONLY | O_NONBLOCK);
    if (fd == -1) return -1;
    fcntl(fd, F_SETFD, 1);
    return fd;
#endif
}
