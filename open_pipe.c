/* taken from public-domain nacl-20110221, from curvecp/open_pipe.c */
#include <unistd.h>
#include <fcntl.h>
#include "open.h"
#include "blocking.h"

int open_pipe(int *fd) {
    int i;
    if (pipe(fd) == -1) return -1;
    for (i = 0; i < 2; ++i) {
        fcntl(fd[i], F_SETFD, 1);
        blocking_disable(fd[i]);
    }
    return 0;
}
