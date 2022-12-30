#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include "timeoutwrite.h"

/*
The function 'timeoutwrite()' writes up to 'len' bytes from the buffer starting
at 'buf' to the file referred to by the file descriptor 'fd' and waits at most
't' seconds.
In the timeoutwrite() function is used select(),
because poll() doesn't work when RLIMIT_NOFILE is set to 0;
*/

long long timeoutwrite(long long t, int fd, const char *buf, long long len) {

    struct timeval tv;
    long long deadline, tm;
    fd_set wfds;

    if (t < 0 || len < 0) {
        errno = EINVAL;
        return -1;
    }

    gettimeofday(&tv, (struct timezone *) 0);
    deadline = 1000000LL * (t + tv.tv_sec) + tv.tv_usec;

    for (;;) {
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);

        gettimeofday(&tv, (struct timezone *) 0);
        tm = deadline - (1000000LL * tv.tv_sec + tv.tv_usec);
        if (tm <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (tm > 1000000000LL) tm = 1000000000LL;
        tv.tv_sec = tm / 1000000LL;
        tv.tv_usec = tm % 1000000LL;
        select(fd + 1, (fd_set *) 0, &wfds, (fd_set *) 0, &tv);
        if (FD_ISSET(fd, &wfds)) break;
    }
    return write(fd, buf, len);
}
