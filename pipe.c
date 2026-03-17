/*
 * pipe.c - length-prefixed pipe I/O helpers
 *
 * Provides small helpers for exchanging framed messages over blocking
 * pipes. Each payload is prefixed with an 8-byte little-endian signed
 * length field so callers can send fixed-size buffers, bounded variable
 * data, or encoded errno values through a simple binary protocol.
 */

#include <string.h>
#include <unistd.h>
#include "e.h"
#include "readall.h"
#include "writeall.h"
#include "alloc.h"
#include "pipe.h"

/*
 * uint64_pack - encode a signed length into 8 bytes
 *
 * @y: destination buffer with room for 8 bytes
 * @xll: signed value to encode
 *
 * Stores @xll as an 8-byte little-endian integer used by the local pipe
 * framing format.
 */
static void uint64_pack(unsigned char *y, long long xll) {

    long long i;
    unsigned long long x = (unsigned long long) xll;

    for (i = 0; i < 8; ++i) {
        y[i] = x;
        x >>= 8;
    }
}

/*
 * uint64_unpack - decode an 8-byte framed length
 *
 * @x: source buffer with 8 encoded bytes
 *
 * Returns the signed length value stored in the local little-endian pipe
 * framing format.
 */
static long long uint64_unpack(const unsigned char *x) {

    unsigned long long y = 0;
    long long i;
    for (i = 7; i >= 0; --i) y = (y << 8) | x[i];
    return (long long) y;
}

/*
 * pipe_write - write one framed payload to a pipe
 *
 * @fd: pipe file descriptor
 * @xv: payload buffer
 * @xlen: payload length in bytes
 *
 * Writes an 8-byte length prefix followed by exactly @xlen bytes from @xv.
 *
 * Constraints:
 *   - @xlen must be non-negative.
 *
 * Returns 0 on success and -1 on failure.
 */
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

/*
 * pipe_writeerrno - write the current errno as a framed negative value
 *
 * @fd: pipe file descriptor
 *
 * Encodes the current errno value as a negative framed length so the peer
 * can distinguish reported errors from normal payload lengths.
 *
 * Returns 0 on success and -1 on failure.
 */
int pipe_writeerrno(int fd) {
    unsigned char num[8];
    uint64_pack(num, -errno);
    if (writeall(fd, num, sizeof num) == -1) goto fail;
    return 0;
fail:
    return -1;
}

/*
 * pipe_readall - read a framed payload with an exact expected size
 *
 * @fd: pipe file descriptor
 * @out: destination buffer
 * @outlen: required payload length in bytes
 *
 * Reads one framed message and copies it into @out only when the encoded
 * payload length exactly matches @outlen.
 *
 * Constraints:
 *   - @out must be non-null.
 *   - @outlen must not exceed 1048576 bytes.
 *
 * Returns 0 on success and -1 on failure.
 */
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

/*
 * pipe_readmax - read a framed payload up to a caller-supplied bound
 *
 * @fd: pipe file descriptor
 * @out: destination buffer
 * @outlen: input maximum size, output actual payload length
 *
 * Reads one framed message into @out when the encoded payload length does
 * not exceed the caller-provided bound in *@outlen. On success, *@outlen
 * is updated to the number of payload bytes read.
 *
 * Constraints:
 *   - @out must be non-null.
 *   - The input value of *@outlen must not exceed 1048576 bytes.
 *
 * Returns 0 on success and -1 on failure.
 */
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

/*
 * pipe_readalloc - allocate and read one framed payload
 *
 * @fd: pipe file descriptor
 * @outlen: output payload length
 *
 * Reads one framed message, allocates a buffer large enough for the payload,
 * and fills it with the received bytes. Negative framed lengths are treated
 * as encoded errno values and restored into errno.
 *
 * Returns the allocated buffer on success, or null on failure.
 */
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
