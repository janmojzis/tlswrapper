#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <grp.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include "jail.h"

#define JAIL_BASEUID 141500000
#define JAIL_MAXPID 1000000000

int jail_droproot(void) {

    uid_t targetuid;
    gid_t targetgid;
    pid_t pid = getpid();

    if (pid < 0 || pid > JAIL_MAXPID) return -1;
    pid += JAIL_BASEUID;
    targetgid = targetuid = pid;

    if (setgroups(1, &targetgid) == -1) return -1;
    if (setgid(targetgid) == -1) return -1;
    if (setuid(targetuid) == -1) return -1;
    if (getgid() != targetgid) return -1;
    if (getuid() != targetuid) return -1;
    return 0;
}


int jail(const char *dir) {

#ifdef RLIM_INFINITY
    struct rlimit r;
    r.rlim_cur = 0;
    r.rlim_max = 0;
#endif


/* prohibit new files, new sockets, etc. */
#ifdef RLIM_INFINITY
#ifdef RLIMIT_NOFILE
    if (setrlimit(RLIMIT_NOFILE, &r) == -1) return -1;
#endif
#endif

    if (geteuid() == 0) {

        /* prohibit access to filesystem */
        if (!dir) return -1;
        if (chdir(dir) == -1) return -1;
        if (chroot(".") == -1) return -1;

        /* prohibit kill, ptrace, etc. */
#ifdef PR_SET_DUMPABLE
        if (prctl(PR_SET_DUMPABLE, 0) == -1) return -1;
#endif
        if (jail_droproot() == -1) return -1;
    }

    /* prohibit fork */
#ifdef RLIM_INFINITY
#ifdef RLIMIT_NPROC
    if (setrlimit(RLIMIT_NPROC, &r) == -1) return -1;
#endif
#endif
    return 0;
}

int jail_poll(struct pollfd *x, nfds_t len, int millisecs) {

    struct timeval *tvp = 0;
    struct timeval tv;
    fd_set rfds;
    fd_set wfds;
    nfds_t nfds;
    int fd, r;
    nfds_t i;

    for (i = 0; i < len; ++i) x[i].revents = 0;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    nfds = 1;
    for (i = 0; i < len; ++i) {
        fd = x[i].fd;
        if (fd < 0) continue;
        if (fd >= (int) (8 * sizeof(fd_set))) continue;
        if ((unsigned int) fd >= nfds) nfds = fd + 1;
        if (x[i].events & POLLIN) FD_SET(fd, &rfds);
        if (x[i].events & POLLOUT) FD_SET(fd ,&wfds);
    }

    if (millisecs >= 0) {
        tv.tv_sec = millisecs / 1000;
        tv.tv_usec = 1000 * (millisecs % 1000);
        tvp = &tv;
    }

    r = select(nfds, &rfds, &wfds, (fd_set *) 0, tvp);
    if (r <= 0) return r;

    r = 0;
    for (i = 0; i < len; ++i) {
        fd = x[i].fd;
        if (fd < 0) continue;
        if (fd >= (int) (8 * sizeof(fd_set))) continue;

        if (x[i].events & POLLIN) {
            if (FD_ISSET(fd, &rfds)) x[i].revents |= POLLIN;
            ++r;
        }
        if (x[i].events & POLLOUT) {
            if (FD_ISSET(fd, &wfds)) x[i].revents |= POLLOUT;
            ++r;
        }
    }
    return r;
}
