#include <unistd.h>
#include <errno.h>
#include "jail.h"
#include "sio.h"

void sio_init(sio *s, long long (*op)(int, void *, long long), int fd,
              void *buf, long long bufsize) {
    s->op = op;
    s->fd = fd;
    s->buf = buf;
    s->bufsize = bufsize;
    s->buflen = 0;
}

long long sio_write(int fd, void *x, long long xlen) {
    return write(fd, x, xlen);
}

static long long allwrite(long long (*op)(int, void *, long long), int fd,
                          const void *xv, long long xlen) {

    char *x = (char *) xv;
    long long w;

    while (xlen > 0) {
        w = xlen;
        if (w > 1048576) w = 1048576;
        w = op(fd, x, w);
        if (w == -1) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd p;
                p.fd = fd;
                p.events = POLLOUT | POLLERR;
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

int sio_flush(sio *s) {
    if (allwrite(s->op, s->fd, s->buf, s->buflen) == -1) return -1;
    s->buflen = 0;
    return 0;
}

int sio_put(sio *s, const void *xv, long long xlen) {

    long long n, i;
    const char *x = xv;

    while (xlen > (n = s->bufsize - s->buflen)) {
        for (i = 0; i < n; ++i) s->buf[s->buflen + i] = x[i];
        x += n;
        xlen -= n;
        s->buflen += n;
        if (sio_flush(s) == -1) return -1;
    }
    for (i = 0; i < xlen; ++i) s->buf[s->buflen + i] = x[i];
    s->buflen += xlen;
    return 0;
}

int sio_puts(sio *s, const char *x) {

    long long xlen;

    for (xlen = 0; x[xlen]; ++xlen)
        ;
    return sio_put(s, x, xlen);
}

int sio_putflush(sio *s, const void *x, long long xlen) {
    if (sio_flush(s) == -1) return -1;
    return allwrite(s->op, s->fd, x, xlen);
}

int sio_putsflush(sio *s, const char *x) {
    long long xlen;
    for (xlen = 0; x[xlen]; ++xlen)
        ;
    return sio_putflush(s, x, xlen);
}

long long sio_read(int fd, void *x, long long xlen) {
    return read(fd, x, xlen);
}

static long long oneread(long long (*op)(int, void *, long long), int fd,
                         void *x, long long xlen) {

    long long r;
    struct pollfd p;

    for (;;) {
        p.fd = fd;
        p.events = POLLIN;
        jail_poll(&p, 1, -1);
        if (xlen > 1048576) xlen = 1048576;
        r = op(fd, x, xlen);
        if (r == -1) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;
            if (errno == EWOULDBLOCK) continue;
        }
        return r;
    }
}

long long sio_getch(sio *s, char *x) {

    long long r, i, j;
    char ch;

    if (s->buflen <= 0) {
        r = oneread(s->op, s->fd, s->buf, s->bufsize);
        if (r <= 0) return r;
        for (i = 0, j = r - 1; i < j; ++i, --j) {
            ch = s->buf[i];
            s->buf[i] = s->buf[j];
            s->buf[j] = ch;
        }
        s->buflen = r;
    }

    *x = s->buf[--s->buflen];
    return 1;
}
