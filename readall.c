#include <unistd.h>
#include "e.h"
#include "readall.h"

int readall(int fd, void *xv, long long xlen) {

    long long r;
    unsigned char *x = (unsigned char *)xv;

    while (xlen > 0) {
        r = xlen;
        if (r > 1048576) r = 1048576;
        r = read(fd, x, r);
        if (r == 0) errno = EPIPE;
        if (r <= 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        x += r;
        xlen -= r;
    }
    return 0;
}
