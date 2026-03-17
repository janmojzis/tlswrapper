/*
 * readall.c - read an exact byte count from a descriptor
 *
 * This helper hides EINTR and transient nonblocking retries for callers
 * that expect a fixed-size read to complete.
 */

#include <unistd.h>
#include "e.h"
#include "readall.h"

/*
 * readall - read exactly xlen bytes
 *
 * @fd: source descriptor
 * @xv: destination buffer
 * @xlen: number of bytes to read
 *
 * Returns 0 after filling the destination buffer. Returns -1 on EOF or
 * on any non-recoverable read error.
 */
int readall(int fd, void *xv, long long xlen) {

    long long r;
    unsigned char *x = (unsigned char *) xv;

    while (xlen > 0) {
        r = xlen;
        if (r > 1048576) r = 1048576;
        r = read(fd, x, r);
        if (r == 0) errno = EPIPE;
        if (r <= 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;
            if (errno == EWOULDBLOCK) continue;
            return -1;
        }
        x += r;
        xlen -= r;
    }
    return 0;
}
