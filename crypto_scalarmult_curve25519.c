/*
20180104
Jan Mojzis
Public domain.
*/

#include "crypto_scalarmult_curve25519.h"

typedef unsigned long fe[8];

/*
o = x
*/
static void fe_copy(fe o, const fe x) {

    long long i;
    for (i = 0; i < 8; ++i) o[i] = x[i];
}

/*
o = 0
*/
static void fe_0(fe o) {

    long long i;
    for (i = 0; i < 8; ++i) o[i] = 0;
}

/*
o = 1
*/
static void fe_1(fe o) {

    fe_0(o);
    o[0] = 1;
}

/*
if (b) swap(f, g)
*/
static void fe_cswap(fe f, fe g, unsigned long b) {

    long long i;
    fe t;

    b = -b;

    for (i = 0; i < 8; ++i) t[i] = b & (f[i] ^ g[i]);
    for (i = 0; i < 8; ++i) f[i] ^= t[i];
    for (i = 0; i < 8; ++i) g[i] ^= t[i];
}

static unsigned long uint32_unpack(const unsigned char *x) {

    unsigned long y = 0;
    long long i;
    for (i = 3; i >= 0; --i) y = (y << 8) | x[i];
    return y;
}

static void fe_frombytes(fe out, const unsigned char *in) {

    long long i;

    /* unpack from little-endian format */
    for (i = 0; i < 8; ++i) out[i] = uint32_unpack(in + 4 * i);
    out[7] &= 0x7fffffff;
}

static void uint32_pack(unsigned char *y, unsigned long x) {

    long long i;
    for (i = 0; i < 4; ++i) {
        y[i] = x;
        x >>= 8;
    }
}

/* select r if r < p, or r + -p if r >= p */
static void fe_squeeze(fe r) {

    unsigned long long pb = 0, b;
    long long i;
    fe t;
    const unsigned long long p[8] = {
        0xffffffedULL, 0xffffffffULL, 0xffffffffULL, 0xffffffffULL,
        0xffffffffULL, 0xffffffffULL, 0xffffffffULL, 0x7fffffffULL,
    };

    for (i = 0; i < 8; ++i) {
        pb += p[i];
        b = (unsigned long long) r[i] - pb;
        b >>= (sizeof(unsigned long long) * 8) - 1;
        t[i] = (unsigned long long) r[i] - pb + (b << 32);
        pb = b;
    }
    b = -pb;
    b >>= (sizeof(unsigned long long) * 8) - 1;
    b -= 1;
    for (i = 0; i < 8; ++i) r[i] ^= b & (r[i] ^ t[i]);
}

static void fe_tobytes(unsigned char *out, const fe in) {

    fe r;
    long long i;

    fe_copy(r, in);
    fe_squeeze(r);
    for (i = 0; i < 8; ++i) uint32_pack(out + 4 * i, r[i]);
}

/*
o = (x * c) % p
*/
static void fe_mulc(fe o, const fe x, const unsigned long long c) {

    unsigned long long u = 0;
    long long i;

    for (i = 0; i < 7; ++i) {
        u += (unsigned long long) x[i] * c;
        o[i] = u & 0xffffffff;
        u >>= 32;
    }
    u += (unsigned long long) x[i] * c;
    o[i] = u & 0x7fffffff;
    u >>= 31;
    u *= 19ULL;
    for (i = 0; i < 8; ++i) {
        u += o[i];
        o[i] = u & 0xffffffff;
        u >>= 32;
    }
}

/*
o = (a * b) % p
*/
static void fe_mul(fe o, const fe a, const fe b) {

    unsigned long long u, t[16];
    long long i;

    for (i = 0; i < 16; ++i) t[i] = 0;

/*
    Unrolled version of:
    for (i = 0; i < 8; ++i) for (j = 0; j < 8; ++j) {
        u = (unsigned long long)a[i] * (unsigned long long)b[j];
        t[i + j    ] += u & 0xffffffff;
        t[i + j + 1] += u >> 32;
    }
*/
/* clang-format off */
#define M(i, j) u = (unsigned long long)a[i] * (unsigned long long)b[j]; \
                 t[i + j    ] += u & 0xffffffff; \
                 t[i + j + 1] += u >> 32;
    M(0, 0); M(0, 1); M(0, 2); M(0, 3); M(0, 4); M(0, 5); M(0, 6); M(0, 7); 
    M(1, 0); M(1, 1); M(1, 2); M(1, 3); M(1, 4); M(1, 5); M(1, 6); M(1, 7); 
    M(2, 0); M(2, 1); M(2, 2); M(2, 3); M(2, 4); M(2, 5); M(2, 6); M(2, 7); 
    M(3, 0); M(3, 1); M(3, 2); M(3, 3); M(3, 4); M(3, 5); M(3, 6); M(3, 7); 
    M(4, 0); M(4, 1); M(4, 2); M(4, 3); M(4, 4); M(4, 5); M(4, 6); M(4, 7); 
    M(5, 0); M(5, 1); M(5, 2); M(5, 3); M(5, 4); M(5, 5); M(5, 6); M(5, 7); 
    M(6, 0); M(6, 1); M(6, 2); M(6, 3); M(6, 4); M(6, 5); M(6, 6); M(6, 7); 
    M(7, 0); M(7, 1); M(7, 2); M(7, 3); M(7, 4); M(7, 5); M(7, 6); M(7, 7);
/* clang-format on */
#undef M

    u = 0;
    for (i = 0; i < 7; ++i) {
        u += t[i] + 38ULL * t[i + 8];
        t[i] = u & 0xffffffff;
        u >>= 32;
    }
    u += t[i] + 38ULL * t[i + 8];
    t[i] = u & 0x7fffffff;
    u >>= 31;
    u *= 19ULL;
    for (i = 0; i < 8; ++i) {
        u += t[i];
        o[i] = u & 0xffffffff;
        u >>= 32;
    }
}

/*
o = (x ^ 2) % p
*/
static void fe_sq(fe o, const fe a) {

    unsigned long long u, t[16];
    long long i;

    for (i = 0; i < 16; ++i) t[i] = 0;

/*
    Unrolled version of:
    for (i = 0; i < 8; ++i) for (j = i + 1; j < 8; ++j) {
        u = (unsigned long long)a[i] * (unsigned long long)a[j];
        t[i + j    ] += 2 * (u & 0xffffffff);
        t[i + j + 1] += 2 * (u >> 32);
    }
    for (i = 0; i < 8; ++i) {
        u = (unsigned long long)a[i] * (unsigned long long)a[i];
        t[2 * i    ] += u & 0xffffffff;
        t[2 * i + 1] += u >> 32;
    }
*/
/* clang-format off */
#define M(i, j) u = (unsigned long long)a[i] * (unsigned long long)a[j]; \
                 t[i + j    ] += (u & 0x00000000ffffffff) <<  1; \
                 t[i + j + 1] += (u & 0xffffffff00000000) >> 31;
     M(0, 1); M(0, 2); M(0, 3); M(0, 4); M(0, 5); M(0, 6); M(0, 7); 
     M(1, 2); M(1, 3); M(1, 4); M(1, 5); M(1, 6); M(1, 7); 
     M(2, 3); M(2, 4); M(2, 5); M(2, 6); M(2, 7); 
     M(3, 4); M(3, 5); M(3, 6); M(3, 7); 
     M(4, 5); M(4, 6); M(4, 7); 
     M(5, 6); M(5, 7); 
     M(6, 7); 
     
#undef M
#define S(i)    u = (unsigned long long)a[i] * (unsigned long long)a[i]; \
                 t[2 * i    ] +=     (u & 0xffffffff); \
                 t[2 * i + 1] +=     (u >> 32)
     S(0); S(1); S(2); S(3); S(4); S(5); S(6); S(7);
/* clang-format on */
#undef S

    u = 0;
    for (i = 0; i < 7; ++i) {
        u += t[i] + 38ULL * t[i + 8];
        t[i] = u & 0xffffffff;
        u >>= 32;
    }
    u += t[i] + 38ULL * t[i + 8];
    t[i] = u & 0x7fffffff;
    u >>= 31;
    u *= 19ULL;
    for (i = 0; i < 8; ++i) {
        u += t[i];
        o[i] = u & 0xffffffff;
        u >>= 32;
    }
}

/*
o = (x + y) % p
*/
static void fe_add(fe o, const fe x, const fe y) {

    unsigned long long u = 0;
    long long i;

    for (i = 0; i < 7; ++i) {
        u += (unsigned long long) x[i] + (unsigned long long) y[i];
        o[i] = u & 0xffffffff;
        u >>= 32;
    }
    u += (unsigned long long) x[i] + (unsigned long long) y[i];
    o[i] = u & 0x7fffffff;
    u >>= 31;
    u *= 19ULL;
    for (i = 0; i < 8; ++i) {
        u += o[i];
        o[i] = u & 0xffffffff;
        u >>= 32;
    }
}

/*
o = (x - y) % p
*/
static void fe_sub(fe o, const fe x, const fe y) {

    long long i;
    unsigned long long u = 0;
    const unsigned long long p4[8] = {
        0x3ffffffb4ULL, 0x3fffffffcULL, 0x3fffffffcULL, 0x3fffffffcULL,
        0x3fffffffcULL, 0x3fffffffcULL, 0x3fffffffcULL, 0x1fffffffcULL,
    };

    for (i = 0; i < 7; ++i) {
        u += p4[i] - (unsigned long long) y[i] + (unsigned long long) x[i];
        o[i] = u & 0xffffffff;
        u >>= 32;
    }
    u += p4[i] - (unsigned long long) y[i] + (unsigned long long) x[i];
    o[i] = u & 0x7fffffff;
    u >>= 31;
    u *= 19ULL;
    for (i = 0; i < 8; ++i) {
        u += o[i];
        o[i] = u & 0xffffffff;
        u >>= 32;
    }
}

/*
o = (1 / z) % p
*/
static void fe_inv(fe o, const fe z) {

    fe t0, t1, t2, t3;
    long long i;

    fe_sq(t0, z);
    for (i = 1; i < 1; ++i) fe_sq(t0, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 2; ++i) fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    for (i = 1; i < 1; ++i) fe_sq(t2, t2);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (i = 1; i < 5; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i = 1; i < 10; ++i) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i = 1; i < 20; ++i) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i = 1; i < 10; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i = 1; i < 50; ++i) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i = 1; i < 100; ++i) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i = 1; i < 50; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 5; ++i) fe_sq(t1, t1);
    fe_mul(o, t1, t0);
}

int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                                 const unsigned char *p) {

    unsigned char e[32];
    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    long long i, pos;
    unsigned int d = 0;
    unsigned long swap, b;

    for (i = 0; i < 32; ++i) e[i] = n[i];
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    fe_frombytes(x1, p);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    swap = 0;
    for (pos = 254; pos >= 0; --pos) {
        b = e[pos / 8] >> (pos & 7);
        b &= 1;
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;

        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mulc(z3, tmp1, 121666);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_inv(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(q, x2);

    for (i = 0; i < 32; ++i) d |= q[i];
    return -(1 & ((d - 1) >> 8));
}

static const unsigned char basepoint[32] = {9};

int crypto_scalarmult_curve25519_base(unsigned char *q,
                                      const unsigned char *n) {
    return crypto_scalarmult_curve25519(q, n, basepoint);
}
