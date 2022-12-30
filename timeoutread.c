#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include "timeoutread.h"

/*
The function 'timeoutread()' attempts to read up to 'len' bytes from file
descriptor 'fd' into the buffer starting at 'buf' and waits at most 't' seconds.
In the timeoutread() function is used select(),
because poll() doesn't work when RLIMIT_NOFILE is set to 0;
*/

long long timeoutread(long long t, int fd, char *buf, long long len) {

    struct timeval tv;
    long long deadline, tm;
    fd_set rfds;

    if (t < 0 || len < 0) {
        errno = EINVAL;
        return -1;
    }

    gettimeofday(&tv, (struct timezone *) 0);
    deadline = 1000000LL * (t + tv.tv_sec) + tv.tv_usec;

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        gettimeofday(&tv, (struct timezone *) 0);
        tm = deadline - (1000000LL * tv.tv_sec + tv.tv_usec);
        if (tm <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (tm > 1000000000LL) tm = 1000000000LL;
        tv.tv_sec = tm / 1000000LL;
        tv.tv_usec = tm % 1000000LL;
        select(fd + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);
        if (FD_ISSET(fd, &rfds)) break;
    }
    return read(fd, buf, len);
}
