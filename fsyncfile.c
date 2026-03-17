/*
 * fsyncfile.c - conditionally synchronize regular files
 *
 * Provides a small wrapper around fsync() that first checks whether a
 * file descriptor refers to a regular file.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "fsyncfile.h"

/*
 * fsyncfile - fsync a regular file descriptor
 *
 * @fd: file descriptor to inspect and synchronize
 *
 * Calls fsync() only when fd refers to a regular file. Returns 0 for
 * non-regular file descriptors without attempting synchronization.
 */
int fsyncfile(int fd) {

    struct stat st;

    if (fstat(fd, &st) == -1) return -1;
    if (!S_ISREG(st.st_mode)) return 0;
    return fsync(fd);
}
