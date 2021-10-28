#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "writeall.h"

/* clang-format off */
static inline uint32_t unpack32(const unsigned char *x) {
    return
        (uint32_t) (x[0])                  \
    | (((uint32_t) (x[1])) << 8)           \
    | (((uint32_t) (x[2])) << 16)          \
    | (((uint32_t) (x[3])) << 24);
}
static inline void pack32(unsigned char *x, uint32_t u) {
    x[0] = u; u >>= 8;
    x[1] = u; u >>= 8;
    x[2] = u; u >>= 8;
    x[3] = u;
}

#define ROTATE(x, c) ((x) << (c)) ^ ((x) >> (32 - (c)))

#define QUARTERROUND(a, b, c, d)                    \
    a += b; d = ROTATE(d ^ a, 16);                  \
    c += d; b = ROTATE(b ^ c, 12);                  \
    a += b; d = ROTATE(d ^ a,  8);                  \
    c += d; b = ROTATE(b ^ c,  7);

#define TWOROUNDS                                   \
    QUARTERROUND( x0, x4,  x8, x12)                 \
    QUARTERROUND( x1, x5,  x9, x13)                 \
    QUARTERROUND( x2, x6, x10, x14)                 \
    QUARTERROUND( x3, x7, x11, x15)                 \
    QUARTERROUND( x0, x5, x10, x15)                 \
    QUARTERROUND( x1, x6, x11, x12)                 \
    QUARTERROUND( x2, x7,  x8, x13)                 \
    QUARTERROUND( x3, x4,  x9, x14)

#define XORBLOCK(o, i)                              \
    x0  = s0;                                       \
    x1  = s1;                                       \
    x2  = s2;                                       \
    x3  = s3;                                       \
    x4  = k0;                                       \
    x5  = k1;                                       \
    x6  = k2;                                       \
    x7  = k3;                                       \
    x8  = k4;                                       \
    x9  = k5;                                       \
    x10 = k6;                                       \
    x11 = k7;                                       \
    x12 = n0;                                       \
    x13 = n1;                                       \
    x14 = n2;                                       \
    x15 = n3;                                       \
                                                    \
    TWOROUNDS /* round  1,  2 */                    \
    TWOROUNDS /* round  3,  4 */                    \
    TWOROUNDS /* round  5,  6 */                    \
    TWOROUNDS /* round  7,  8 */                    \
                                                    \
    pack32(o     ,  (x0 + s0) ^ unpack32(i     ));  \
    pack32(o +  4,  (x1 + s1) ^ unpack32(i +  4));  \
    pack32(o +  8,  (x2 + s2) ^ unpack32(i +  8));  \
    pack32(o + 12,  (x3 + s3) ^ unpack32(i + 12));  \
    pack32(o + 16,  (x4 + k0) ^ unpack32(i + 16));  \
    pack32(o + 20,  (x5 + k1) ^ unpack32(i + 20));  \
    pack32(o + 24,  (x6 + k2) ^ unpack32(i + 24));  \
    pack32(o + 28,  (x7 + k3) ^ unpack32(i + 28));  \
    pack32(o + 32,  (x8 + k4) ^ unpack32(i + 32));  \
    pack32(o + 36,  (x9 + k5) ^ unpack32(i + 36));  \
    pack32(o + 40, (x10 + k6) ^ unpack32(i + 40));  \
    pack32(o + 44, (x11 + k7) ^ unpack32(i + 44));  \
    pack32(o + 48, (x12 + n0) ^ unpack32(i + 48));  \
    pack32(o + 52, (x13 + n1) ^ unpack32(i + 52));  \
    pack32(o + 56, (x14 + n2) ^ unpack32(i + 56));  \
    pack32(o + 60, (x15 + n3) ^ unpack32(i + 60));

int crypto_stream_chacha8_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    register uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    register uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t k0 = unpack32(k     );
    uint32_t k1 = unpack32(k +  4);
    uint32_t k2 = unpack32(k +  8);
    uint32_t k3 = unpack32(k + 12);
    uint32_t k4 = unpack32(k + 16);
    uint32_t k5 = unpack32(k + 20);
    uint32_t k6 = unpack32(k + 24);
    uint32_t k7 = unpack32(k + 28);
    uint32_t n0 = 0;
    uint32_t n1 = 0;
    uint32_t n2 = unpack32(n    );
    uint32_t n3 = unpack32(n + 4);
    uint32_t s0 = 0x61707865;
    uint32_t s1 = 0x3320646E;
    uint32_t s2 = 0x79622D32;
    uint32_t s3 = 0x6B206574;
    uint64_t u = 0;

    if (!l) return 0;

    while (l >= 64) {
        XORBLOCK(c, m);

        if (!++u) return -1;
        n0 = u;
        n1 = u >> 32;

        l -= 64;
        c += 64;
        m += 64;
    }
    if (l) {
        unsigned char b[64] = {0};
        unsigned long long j;

        for (j = 0; j < l; ++j) b[j] = m[j];
        XORBLOCK(b, b);
        for (j = 0; j < l; ++j) c[j] = b[j];
    }
    return 0;
}

int crypto_stream_chacha8(unsigned char *c, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    unsigned long long j;
    unsigned char ncopy[8], kcopy[32];

    for (j = 0; j < 32; ++j) kcopy[j] = k[j];
    for (j = 0; j <  8; ++j) ncopy[j] = n[j];
    for (j = 0; j <  l; ++j) c[j] = 0;
    return crypto_stream_chacha8_xor(c, c, l, ncopy, kcopy);
}
/* clang-format on */

static void uint64_pack(unsigned char *y, unsigned long long x) {

    unsigned long long i;
    for (i = 0; i < 8; ++i) { y[i] = x; x >>= 8; }
}

static unsigned char buf[8192];
uint64_t c = 0;
static unsigned char n[8];
static unsigned char k[32] = {0};

long long readblock(int fd, void *x, long long xlen) {

    long long r;
    char *buf = x;

    while (xlen > 0) {
        r = xlen;
        if (r > 1048576) r = 1048576;
        r = read(fd, buf, r);
        if (r == 0) break;
        if (r == -1) return -1;
        buf += r; xlen -= r;
    }
    return (buf - (char *)x);
}

void recv(void) {
    long long len, i, pos = -1;

    for (;;) {
        len = readblock(0, buf, sizeof buf);
        if (len == -1) _exit(111);
        uint64_pack(n, c++);
        crypto_stream_chacha8_xor(buf, buf, len, n, k);
        for (i = 0; i < len; ++i) if (buf[i] != 0) { pos = i; break; }
        if (len != sizeof buf) break;
    }
    if (pos >= 0) {
        fprintf(stderr, "failed on position: %llu\n", pos + (sizeof buf) * (c - 1));
    }
    else {
        fprintf(stderr, "bytes received successfuly: %llu\n", len  + (sizeof buf) * (c - 1));
    }
    fflush(stderr);
}

void send(long long len) {

    long long r;

    while (len > 0) {
        r = len;
        if (r > (long long)(sizeof buf)) r = (long long)(sizeof buf);
        uint64_pack(n, c++);
        crypto_stream_chacha8(buf, sizeof buf, n, k);
        if (writeall(1, buf, r) == -1) _exit(111);
        len -= r;
    }
}

int main(int argc, char **argv) {

    (void) argc;

    if (!argv[0]) _exit(100);

    if (argv[1]) {
        send(atoll(argv[1]));
    }
    else {
        recv();
    }

    _exit(0);
}
