/*
 * buffer.c - buffered I/O helpers for descriptors
 *
 * This module provides reusable input and output buffers with retry-aware
 * read and write helpers for descriptor-based I/O.
 *
 * version 20220222
 */

#include <unistd.h>
#include <errno.h>
#include "buffer.h"

/*
 * buffer_init - initialize a buffer structure
 *
 * @s: buffer state to initialize
 * @op: backend read or write callback
 * @fd: descriptor used by @op
 * @x: caller-provided storage
 * @xlen: size of @x in bytes
 *
 * Resets the buffer state to use the provided callback, descriptor, and
 * storage area. Negative storage sizes are clamped to zero.
 */
void buffer_init(buffer *s, long long (*op)(int, void *, long long), int fd,
                 void *x, long long xlen) {

    s->x = (char *) x;
    s->fd = fd;
    s->op = op;
    s->p = 0;
    s->n = xlen;
    if (s->n < 0) s->n = 0;
}

/*
 * buffer_write - default write backend for output buffers
 *
 * @fd: destination descriptor
 * @x: source bytes
 * @xlen: number of bytes to write
 *
 * Returns the underlying write() result and rejects negative lengths.
 */
long long buffer_write(int fd, void *x, long long xlen) {

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

/*
 * buffer_flush - write buffered output to the descriptor
 *
 * @s: buffer state
 *
 * Returns 0 on success and resets the buffered byte count.
 */
int buffer_flush(buffer *s) {

    if (allwrite(s->op, s->fd, s->x, s->p) < 0) return -1;
    s->p = 0;
    return 0;
}

/*
 * buffer_put - append bytes to an output buffer
 *
 * @s: buffer state
 * @xv: source bytes
 * @xlen: number of bytes to append
 *
 * Flushes as needed and falls back to direct writes for large payloads.
 */
int buffer_put(buffer *s, const void *xv, long long xlen) {

    const char *x = (const char *) xv;
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

/*
 * buffer_puts - append a NUL-terminated string to an output buffer
 *
 * @s: buffer state
 * @x: source string
 *
 * Returns buffer_put() for the string length excluding the trailing NUL.
 */
int buffer_puts(buffer *s, const char *x) {

    long long xlen;

    for (xlen = 0; x[xlen]; ++xlen);
    return buffer_put(s, x, xlen);
}

/*
 * buffer_putflush - flush pending output and write a new payload
 *
 * @s: buffer state
 * @xv: source bytes
 * @xlen: number of bytes to write
 *
 * Returns 0 on success and leaves no buffered output behind.
 */
int buffer_putflush(buffer *s, const void *xv, long long xlen) {

    if (xlen < 0) {
        errno = EINVAL;
        return -1;
    }
    if (buffer_flush(s) == -1) return -1;
    return allwrite(s->op, s->fd, xv, xlen);
}

/*
 * buffer_putsflush - flush pending output and write a string
 *
 * @s: buffer state
 * @x: source string
 *
 * Returns buffer_putflush() for the string length excluding the trailing NUL.
 */
int buffer_putsflush(buffer *s, const char *x) {

    long long xlen;

    for (xlen = 0; x[xlen]; ++xlen);
    return buffer_putflush(s, x, xlen);
}

/*
 * buffer_read - default read backend for input buffers
 *
 * @fd: source descriptor
 * @x: destination bytes
 * @xlen: maximum bytes to read
 *
 * Returns the underlying read() result and rejects negative lengths.
 */
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

/*
 * buffer_feed - refill buffered input
 *
 * @s: buffer state
 *
 * Returns the number of bytes now available in the internal buffer, or a
 * read result <= 0 on EOF or failure.
 */
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

/*
 * getthis - copy bytes out of the buffered input window
 *
 * @s: buffer state
 * @x: destination buffer
 * @xlen: requested byte count
 *
 * Returns the number of bytes copied and advances the buffered read cursor.
 */
static long long getthis(buffer *s, char *x, long long xlen) {

    long long i;

    if (xlen > s->p) xlen = s->p;
    s->p -= xlen;
    for (i = 0; i < xlen; ++i) x[i] = s->x[s->n + i];
    s->n += xlen;
    return xlen;
}

/*
 * buffer_get - read bytes from a buffered input stream
 *
 * @s: buffer state
 * @xv: destination buffer
 * @xlen: requested byte count
 *
 * Returns the number of bytes copied or a read result <= 0 on EOF or failure.
 */
long long buffer_get(buffer *s, void *xv, long long xlen) {

    long long r;

    if (xlen < 0) {
        errno = EINVAL;
        return -1;
    }
    if (s->p > 0) return getthis(s, (char *) xv, xlen);
    if (s->n <= xlen) return oneread(s->op, s->fd, xv, xlen);
    r = buffer_feed(s);
    if (r <= 0) return r;
    return getthis(s, (char *) xv, xlen);
}

/*
 * buffer_copy - copy all data from one buffer to another
 *
 * @bout: destination buffer
 * @bin: source buffer
 *
 * Returns 0 on EOF, -2 on input failure, and -3 on output failure.
 */
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
