/*
version 20220208
*/

#include <unistd.h>
#include <errno.h>
#include "buffer.h"

void buffer_init(buffer *s, long long (*op)(int, void *, long long), int fd,
                 void *x, long long xlen) {

    s->x = x;
    s->fd = fd;
    s->op = op;
    s->p = 0;
    s->n = xlen;
    if (s->n < 0) s->n = 0;
}

long long buffer_write(int fd, const void *x, long long xlen) {

    if (xlen < 0) {
        errno = EINVAL;
        return -1;
    }
    return write(fd, x, xlen);
}

static int allwrite(long long (*op)(int, void *, long long), int fd,
                    const void *xv, long long xlen) {

    char *x = (char *) xv;
    long long w;

    while (xlen > 0) {
        w = xlen;
        if (w > BUFFER_OUTSIZE) w = BUFFER_OUTSIZE;
        w = op(fd, x, w);
        if (w == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        x += w;
        xlen -= w;
    }
    return 0;
}

int buffer_flush(buffer *s) {

    if (allwrite(s->op, s->fd, s->x, s->p) < 0) return -1;
    s->p = 0;
    return 0;
}

int buffer_put(buffer *s, const void *xv, long long xlen) {

    char *x = (char *) xv;
    long long i, n;

    if (xlen < 0) {
        errno = EINVAL;
        return -1;
    }
    if (xlen > (n = s->n - s->p)) {
        for (i = 0; i < n; ++i) s->x[s->p + i] = x[i];
        s->p += n;
        x += n;
        xlen -= n;
        if (buffer_flush(s) == -1) return -1;
    }
    if (xlen >= s->n) return allwrite(s->op, s->fd, x, xlen);
    for (i = 0; i < xlen; ++i) s->x[s->p + i] = x[i];
    s->p += xlen;
    return 0;
}

int buffer_puts(buffer *s, const char *x) {

    long long xlen;

    for (xlen = 0; x[xlen]; ++xlen)
        ;
    return buffer_put(s, x, xlen);
}

int buffer_putflush(buffer *s, const void *xv, long long xlen) {

    if (xlen < 0) {
        errno = EINVAL;
        return -1;
    }
    if (buffer_flush(s) == -1) return -1;
    return allwrite(s->op, s->fd, xv, xlen);
}

int buffer_putsflush(buffer *s, const char *x) {

    long long xlen;

    for (xlen = 0; x[xlen]; ++xlen)
        ;
    return buffer_putflush(s, x, xlen);
}

long long buffer_read(int fd, void *x, long long xlen) {

    if (xlen < 0) {
        errno = EINVAL;
        return -1;
    }
    return read(fd, x, xlen);
}

static long long oneread(long long (*op)(int, void *, long long), int fd,
                         void *x, long long xlen) {
    long long r;

    for (;;) {
        if (xlen > BUFFER_INSIZE) xlen = BUFFER_INSIZE;
        r = op(fd, x, xlen);
        if (r == -1 && errno == EINTR) continue;
        return r;
    }
}

long long buffer_feed(buffer *s) {

    long long i, r;

    if (s->p) return s->p;
    r = oneread(s->op, s->fd, s->x, s->n);
    if (r <= 0) return r;
    s->p = r;
    s->n -= r;
    if (s->n > 0)
        for (i = r - 1; i >= 0; --i) s->x[s->n + i] = s->x[i];
    return r;
}

static long long getthis(buffer *s, char *x, long long xlen) {

    long long i;

    if (xlen > s->p) xlen = s->p;
    s->p -= xlen;
    for (i = 0; i < xlen; ++i) x[i] = s->x[s->n + i];
    s->n += xlen;
    return xlen;
}

long long buffer_get(buffer *s, void *xv, long long xlen) {

    long long r;

    if (xlen < 0) {
        errno = EINVAL;
        return -1;
    }
    if (s->p > 0) return getthis(s, xv, xlen);
    if (s->n <= xlen) return oneread(s->op, s->fd, xv, xlen);
    r = buffer_feed(s);
    if (r <= 0) return r;
    return getthis(s, xv, xlen);
}

int buffer_copy(buffer *bout, buffer *bin) {

    long long n;
    char *x;

    for (;;) {
        n = buffer_feed(bin);
        if (n < 0) return -2;
        if (!n) return 0;
        x = buffer_PEEK(bin);
        if (buffer_put(bout, x, n) == -1) return -3;
        buffer_SEEK(bin, n);
    }
}
