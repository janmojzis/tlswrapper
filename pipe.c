#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "e.h"
#include "readall.h"
#include "writeall.h"
#include "alloc.h"
#include "pipe.h"

static void uint64_pack(unsigned char *y, long long xll) {

    long long i;
    unsigned long long x = (unsigned long long) xll;
    for (i = 0; i < 8; ++i) { y[i] = x; x >>= 8; }
}

static long long uint64_unpack(const unsigned char *x) {

    unsigned long long y = 0;
    long long i;
    for (i = 7; i >= 0; --i) y = (y << 8) | x[i];
    return (long long) y;
}

int pipe_write(int fd, const void *xv, long long xlen) {
    unsigned char num[8];
    if (xlen < 0) {
        errno = EINVAL;
        goto cleanup;
    }
    uint64_pack(num, xlen);
    if (writeall(fd, num, sizeof num) == -1) goto cleanup;
    if (writeall(fd, xv, xlen) == -1) goto cleanup;
    return 0;
cleanup:
    return -1;
}

int pipe_writefn(int fd, const char *dir, const char *name) {

    unsigned char num[8];
    unsigned long long name_len = strlen(name);
    unsigned long long dir_len = 0;
    unsigned long long len = name_len + 1;

    if (dir) {
        dir_len = strlen(dir);
        len += dir_len + 1;
    }

    uint64_pack(num, len);
    if (writeall(fd, num, sizeof num) == -1) goto fail;
    if (dir) {
        if (writeall(fd, dir, dir_len) == -1) goto fail;
        if (writeall(fd, "/", 1) == -1) goto fail;
    }
    if (writeall(fd, name, name_len) == -1) goto fail;
    if (writeall(fd, "", 1) == -1) goto fail;
    return 0;
fail:
    return -1;
}

int pipe_writeerrno(int fd) {
    unsigned char num[8];
    uint64_pack(num, -errno);
    if (writeall(fd, num, sizeof num) == -1) goto fail;
    return 0;
fail:
    return -1;
}

int pipe_readall(int fd, void *out, size_t outlen) {
    unsigned char num[8];
    size_t len;

    if (!out || outlen > 1048576) {
        errno = EINVAL;
        goto cleanup;
    }

    if (readall(fd, num, sizeof num) == -1) goto cleanup;
    len = uint64_unpack(num);
    if (len != outlen) goto cleanup;
    return readall(fd, out, len);
cleanup:
    return -1;
}

int pipe_readmax(int fd, void *out, size_t *outlen) {
    unsigned char num[8];
    size_t len;

    if (!out || *outlen > 1048576) {
        errno = EINVAL;
        goto cleanup;
    }

    if (readall(fd, num, sizeof num) == -1) goto cleanup;
    len = uint64_unpack(num);
    if (len > *outlen) goto cleanup;
    if (readall(fd, out, len) == -1) goto cleanup;
    *outlen = len;
    return 0;

cleanup:
    return -1;
}

void *pipe_readalloc(int fd, size_t *outlen) {

    unsigned char num[8];
    long long len;
    void *out;

    if (readall(fd, num, sizeof num) == -1) goto cleanup;
    len = uint64_unpack(num);
    if (len < 0) {
        errno = -len;
        goto cleanup;
    }
    errno = 0;
    out = alloc(len);
    if (!out) goto cleanup;
    *outlen = len;
    if (readall(fd, out, *outlen) == -1) goto cleanup;
    return out;
cleanup:
    return 0;
}
