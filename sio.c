#include <unistd.h>
#include "e.h"
#include "jail.h"
#include "sio.h"

void sio_init(sio *s, long long (*op)(int, void *, long long), int fd,
              char *buf, long long bufsize) {
    s->op = op;
    s->fd = fd;
    s->buf = buf;
    s->bufsize = bufsize;
    s->buflen = 0;
}

long long sio_write(int fd, void *xv, long long xlen) {

    const unsigned char *x = xv;
    long long ret = xlen;
    long long w;

    if (fd < 0 || !xv || xlen < 0) {
        errno = EINVAL;
        return -1;
    }

    while (xlen > 0) {
        w = xlen;
        if (w > 1048576) w = 1048576;
        w = write(fd, x, w);
        if (w < 0) {
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
    return ret;
}

int sio_flush(sio *s) {
    if (s->op(s->fd, s->buf, s->buflen) == -1) return -1;
    s->buflen = 0;
    return 0;
}

int sio_putch(sio *s, const char x) {
    if ((unsigned long long) (s->buflen) >= sizeof s->buf) {
        if (sio_flush(s) == -1) return -1;
    }
    s->buf[s->buflen++] = x;
    return 0;
}

int sio_puts(sio *s, const char *x) {
    long long i;
    for (i = 0; x[i]; ++i) {
        if ((unsigned long long) (s->buflen) >= sizeof s->buf) {
            if (sio_flush(s) == -1) return -1;
        }
        s->buf[s->buflen++] = x[i];
    }
    return 0;
}

long long sio_read(int fd, void *x, long long xlen) {

    long long r = -1;

    if (fd < 0 || !x || xlen < 0) {
        errno = EINVAL;
        goto cleanup;
    }

    do { r = read(fd, x, xlen); } while (r == -1 && errno == EINTR);

cleanup:
    return r;
}

long long sio_getch(sio *s, char *x) {

    long long r, i, j;
    char ch;

    if (s->buflen <= 0) {
        r = s->op(s->fd, s->buf, s->bufsize);
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
