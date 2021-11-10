/*
20140318
Jan Mojzis
Public domain.
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include "log.h"
#include "randombytes.h"


static int readall(int fd, unsigned char *x, long long xlen) {

    long long r;

    while (xlen > 0) {
        r = read(fd, x, xlen);
        if (r <= 0) return -1;
        x += r;
        xlen -= r;
    }
    return 0;
}

static int writeall(int fd, unsigned char *x, long long xlen) {

    long long r;

    while (xlen > 0) {
        r = write(fd, x, xlen);
        if (r <= 0) return -1;
        x += r;
        xlen -= r;
    }
    return 0;
}

static void fail(char *x) {
    log_f1(x);
    _exit(1);
}


static void run(unsigned char *x, long long xlen) {

    pid_t pid;
    int status, fromchild[2];
    unsigned char buf[16];

    if (pipe(fromchild) == -1) fail("pipe() failure");
    pid = fork();
    if (pid == -1) fail("fork() failure");
    if (pid == 0) {
        close(fromchild[0]);
        randombytes(buf, sizeof buf);
        if (writeall(fromchild[1], buf, sizeof buf) == -1) _exit(1);
        _exit(0);
    }
    close(fromchild[1]);

    if (readall(fromchild[0], x, xlen) == -1) fail("read() failure");

    while (waitpid(pid, &status, 0) != pid) {};
    if (!WIFEXITED(status)) fail("process killed");
    if (WEXITSTATUS(status)) fail("process exited with status != 0");
}

int main(void) {

    unsigned char buf1[16];
    unsigned char buf2[16];

    log_level(4);
    log_name("testrandombytes");

    run(buf1, sizeof buf1);
    run(buf2, sizeof buf2);
    if (memcmp(buf1, buf2, 16) == 0) fail("randombytes() cryptographically dangerous");

    randombytes(buf1, sizeof buf1);
    randombytes(buf2, sizeof buf2);
    if (memcmp(buf1, buf2, 16) == 0) fail("randombytes() cryptographically dangerous");

    run(buf1, sizeof buf1);
    run(buf2, sizeof buf2);
    if (memcmp(buf1, buf2, 16) == 0) fail("randombytes() cryptographically dangerous across fork()");

    _exit(0);
}
