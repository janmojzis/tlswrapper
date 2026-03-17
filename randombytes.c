/*
 * randombytes.c - fill buffers from the system random source
 *
 * This module reads entropy from /dev/urandom when no external
 * randombytes provider is available.
 */

#include "randombytes.h"

#include "haslibrandombytes.h"
#ifndef HASLIBRANDOMBYTES
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static int fd = -1;

/*
 * init - open the kernel random source lazily
 *
 * Repeats until /dev/urandom can be opened and stores the descriptor
 * in the module-global state.
 */
__attribute__((constructor)) static void init(void) {
    if (fd == -1) {
        for (;;) {
#ifdef O_CLOEXEC
            fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
#else
            fd = open("/dev/urandom", O_RDONLY);
            if (fd != -1) fcntl(fd, F_SETFD, 1);
#endif
            if (fd != -1) break;
            sleep(1);
        }
    }
}

/*
 * randombytes - fill a buffer with random bytes
 *
 * @xv: destination buffer
 * @xlen: number of bytes to write
 *
 * Reads from the initialized random source until the whole buffer is
 * filled. Short or failed reads are retried after a short sleep.
 */
void randombytes(void *xv, long long xlen) {

    long long i;
    unsigned char *x = xv;

    if (fd == -1) init();

    while (xlen > 0) {
        if (xlen < 1048576)
            i = xlen;
        else
            i = 1048576;

        i = read(fd, x, i);
        if (i < 1) {
            sleep(1);
            continue;
        }

        x += i;
        xlen -= i;
    }
#ifdef __GNUC__
    __asm__ __volatile__("" : : "r"(xv) : "memory");
#endif
}

const char *randombytes_source(void) { return "kernel-devurandom"; }

#endif
