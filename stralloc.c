/*
 * stralloc.c - dynamically growing byte and string buffers
 *
 * Provides append, copy, numeric formatting, and cleanup helpers for the
 * project's resizable string buffer type.
 */

#include <errno.h>
#include "alloc.h"
#include "stralloc.h"

/*
 * stralloc_readyplus - ensure spare capacity in a stralloc buffer
 *
 * @r: destination buffer
 * @len: additional bytes required
 *
 * Grows r so it can append len more bytes plus a trailing NUL slot
 * without reallocating again.
 *
 * Constraints:
 *   - r must not be NULL
 *   - len must be non-negative
 *
 * Returns 1 on success and 0 on failure.
 */
int stralloc_readyplus(stralloc *r, long long len) {

    char *newdata;
    long long i;
    long long newalloc;

    if (!r || len < 0) {
        errno = EINVAL;
        return 0;
    }
    if (len == 0) return 1;

    if (r->len + len + 1 > r->alloc) {
        newalloc = r->alloc;
        while (r->len + len + 1 > newalloc) newalloc = 2 * newalloc + 32;
        newdata = alloc(newalloc);
        if (!newdata) return 0;
        if (r->s) {
            for (i = 0; i < r->len; ++i) newdata[i] = r->s[i];
            alloc_free(r->s);
        }
        r->s = newdata;
        r->alloc = newalloc;
    }
    return 1;
}

/*
 * stralloc_catb - append raw bytes to a stralloc buffer
 *
 * @r: destination buffer
 * @xv: source bytes
 * @xlen: number of bytes to append
 *
 * Appends xlen bytes to r without adding a terminating NUL.
 *
 * Constraints:
 *   - r and xv must not be NULL
 *   - xlen must be non-negative
 *
 * Returns 1 on success and 0 on failure.
 */
int stralloc_catb(stralloc *r, const void *xv, long long xlen) {

    const char *x = xv;
    long long i;

    if (!r || !xv || xlen < 0) {
        errno = EINVAL;
        return 0;
    }
    if (xlen == 0) return 1;

    if (!stralloc_readyplus(r, xlen)) return 0;
    for (i = 0; i < xlen; ++i) r->s[r->len + i] = x[i];
    r->len += xlen;
    return 1;
}

/*
 * stralloc_cats - append a NUL-terminated string to a stralloc buffer
 *
 * @r: destination buffer
 * @xv: source string
 *
 * Appends the string bytes up to but not including the terminating NUL.
 *
 * Returns 1 on success and 0 on failure.
 */
int stralloc_cats(stralloc *r, const void *xv) {

    const char *x = xv;
    long long xlen;

    if (!r || !xv) {
        errno = EINVAL;
        return 0;
    }

    for (xlen = 0; x[xlen]; ++xlen);
    return stralloc_catb(r, x, xlen);
}

/*
 * stralloc_cat - append one stralloc buffer to another
 *
 * @x: destination buffer
 * @y: source buffer
 *
 * Appends y->len bytes from y to x.
 *
 * Returns 1 on success and 0 on failure.
 */
int stralloc_cat(stralloc *x, stralloc *y) {

    if (!y) {
        errno = EINVAL;
        return 0;
    }

    return stralloc_catb(x, y->s, y->len);
}

/*
 * stralloc_copyb - replace a stralloc buffer with raw bytes
 *
 * @r: destination buffer
 * @xv: source bytes
 * @xlen: number of bytes to copy
 *
 * Clears the logical contents of r and appends xlen bytes from xv.
 *
 * Returns 1 on success and 0 on failure.
 */
int stralloc_copyb(stralloc *r, const void *xv, long long xlen) {

    if (!r) {
        errno = EINVAL;
        return 0;
    }

    r->len = 0;
    return stralloc_catb(r, xv, xlen);
}

/*
 * stralloc_copys - replace a stralloc buffer with a C string
 *
 * @r: destination buffer
 * @xv: source string
 *
 * Clears the logical contents of r and appends the bytes from xv up to
 * the terminating NUL.
 *
 * Returns 1 on success and 0 on failure.
 */
int stralloc_copys(stralloc *r, const void *xv) {

    if (!r) {
        errno = EINVAL;
        return 0;
    }

    r->len = 0;
    return stralloc_cats(r, xv);
}

/*
 * stralloc_copy - replace one stralloc buffer with another
 *
 * @x: destination buffer
 * @y: source buffer
 *
 * Clears x and appends the current contents of y.
 *
 * Returns 1 on success and 0 on failure.
 */
int stralloc_copy(stralloc *x, stralloc *y) {

    if (!x || !y) {
        errno = EINVAL;
        return 0;
    }

    x->len = 0;
    return stralloc_cat(x, y);
}

/*
 * stralloc_append - append a single byte to a stralloc buffer
 *
 * @r: destination buffer
 * @xv: address of the byte to append
 *
 * Returns stralloc_catb() for a one-byte append.
 */
int stralloc_append(stralloc *r, const void *xv) {
    return stralloc_catb(r, xv, 1);
}

/*
 * stralloc_0 - append a trailing NUL byte
 *
 * @r: destination buffer
 *
 * Appends a single zero byte so callers can expose the current contents as
 * a C string.
 *
 * Returns 1 on success and 0 on failure.
 */
int stralloc_0(stralloc *r) { return stralloc_append(r, ""); }

/*
 * stralloc_catunum0 - append an unsigned decimal number with zero padding
 *
 * @sa: destination buffer
 * @u: unsigned value to format
 * @n: minimum field width
 *
 * Formats u in decimal, left-padding with zeroes until at least n digits
 * are written.
 *
 * Returns 1 on success and 0 on failure.
 */
static int stralloc_catunum0(stralloc *sa, unsigned long long u, long long n) {

    long long len;
    unsigned long long q;
    char *s;

    if (!sa) {
        errno = EINVAL;
        return 0;
    }

    len = 1;
    q = u;
    while (q > 9) {
        ++len;
        q /= 10;
    }
    if (len < n) len = n;

    if (!stralloc_readyplus(sa, len)) return 0;
    s = sa->s + sa->len;
    sa->len += len;
    while (len) {
        s[--len] = '0' + (u % 10);
        u /= 10;
    }

    return 1;
}

/*
 * stralloc_catnum0 - append a signed decimal number with zero padding
 *
 * @sa: destination buffer
 * @l: signed value to format
 * @n: minimum digit count excluding any leading minus sign
 *
 * Formats l in decimal and prepends a minus sign for negative values.
 *
 * Returns 1 on success and 0 on failure.
 */
int stralloc_catnum0(stralloc *sa, long long l, long long n) {

    if (!sa) {
        errno = EINVAL;
        return 0;
    }

    if (l < 0) {
        if (!stralloc_append(sa, "-")) return 0;
        l = -l;
    }
    return stralloc_catunum0(sa, l, n);
}

/*
 * stralloc_catnum - append a signed decimal number
 *
 * @r: destination buffer
 * @num: signed value to format
 *
 * Returns stralloc_catnum0() without additional zero padding.
 */
int stralloc_catnum(stralloc *r, long long num) {
    return stralloc_catnum0(r, num, 0);
}

/*
 * stralloc_copynum - replace a stralloc buffer with a decimal number
 *
 * @r: destination buffer
 * @num: signed value to format
 *
 * Clears r and appends num in decimal.
 *
 * Returns 1 on success and 0 on failure.
 */
int stralloc_copynum(stralloc *r, long long num) {

    if (!r) {
        errno = EINVAL;
        return 0;
    }

    r->len = 0;
    return stralloc_catnum(r, num);
}

/*
 * stralloc_free - release storage owned by a stralloc buffer
 *
 * @r: buffer to clear
 *
 * Frees the backing allocation, if any, and resets the stralloc state to
 * an empty buffer.
 */
void stralloc_free(stralloc *r) {

    if (!r) return;
    if (r->s) alloc_free(r->s);
    r->s = 0;
    r->len = 0;
    r->alloc = 0;
}
