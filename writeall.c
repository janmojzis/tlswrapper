/*
 * writeall.c - write an exact byte count to a descriptor
 *
 * This helper retries transient write failures and waits for writable
 * readiness when a nonblocking descriptor would block.
 */

#include <unistd.h>
#include "e.h"
#include "jail.h"
#include "writeall.h"

/*
 * writeall - write exactly xlen bytes
 *
 * @fd: destination descriptor
 * @xv: source buffer
 * @xlen: number of bytes to write
 *
 * Returns 0 after the whole buffer is written. Returns -1 on any
 * non-recoverable write or poll failure.
 */
int writeall(int fd, const void *xv, long long xlen) {

    const unsigned char *x = (const unsigned char *) xv;
    long long w;
    while (xlen > 0) {
        w = xlen;
        if (w > 1048576) w = 1048576;
        w = write(fd, x, w);
        if (w < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd p;
                p.fd = fd;
                p.events = POLLOUT;
                jail_poll(&p, 1, -1);
                continue;
            }
            return -1;
        }
        x += w;
        xlen -= w;
    }
    return 0;
}
