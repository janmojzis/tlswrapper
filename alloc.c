/*
 * alloc.c - small allocator with tracked heap fallback
 *
 * This module provides aligned allocations from a static arena first and
 * falls back to malloc() when the arena is exhausted.
 *
 * Heap-backed allocations are tracked so callers can wipe and release all
 * outstanding memory through alloc_freeall().
 *
 * version 20220222
 */

#include <stdlib.h>
#include <errno.h>
#include "log.h"
#include "alloc.h"

static unsigned char space[alloc_STATICSPACE]
    __attribute__((aligned(alloc_ALIGNMENT)));
static unsigned long long avail = sizeof space;
static unsigned long long allocated = 0;

static void **ptr = 0;
static unsigned long long ptrlen = 0;
static unsigned long long ptralloc = 0;

/*
 * ptr_add - remember a heap allocation for bulk cleanup
 *
 * @x: allocation returned to the caller
 *
 * Returns 1 on success. Null pointers are ignored so callers can keep
 * cleanup code simple.
 */
static int ptr_add(void *x) {

    void **newptr;
    unsigned long long i;

    if (!x) return 1;
    if (ptrlen + 1 > ptralloc) {
        while (ptrlen + 1 > ptralloc) ptralloc = 2 * ptralloc + 1;
        newptr = (void **) malloc(ptralloc * sizeof(void *));
        if (!newptr) return 0;
        if (ptr) {
            for (i = 0; i < ptrlen; ++i) newptr[i] = ptr[i];
            free(ptr);
        }
        ptr = newptr;
    }
    ptr[ptrlen++] = x;
    return 1;
}

/*
 * ptr_remove - forget a tracked heap allocation
 *
 * @x: allocation to remove from the tracker
 *
 * Returns 1 when @x was present in the tracking array.
 */
static int ptr_remove(void *x) {

    unsigned long long i;

    for (i = 0; i < ptrlen; ++i) {
        if (ptr[i] == x) goto ok;
    }
    return 0;
ok:
    --ptrlen;
    ptr[i] = ptr[ptrlen];
    return 1;
}

/*
 * cleanup - wipe a buffer through a volatile view
 *
 * @xv: buffer to clear
 * @xlen: buffer size in bytes
 *
 * Clears whole machine words and uses an asm barrier to keep the write
 * from being optimized away.
 *
 * Security:
 *   - attempts to preserve the memory wipe
 */
static void cleanup(void *xv, unsigned long long xlen) {

    volatile unsigned long *x = (volatile unsigned long *) xv;

    xlen /= sizeof(unsigned long);
    while (xlen-- > 0) *x++ = 0;

    __asm__ __volatile__("" : : "r"(xv) : "memory");
}

/*
 * alloc - allocate aligned storage from the arena or heap
 *
 * @norig: requested allocation size in bytes
 *
 * Returns aligned storage for at least @norig bytes. Zero-length requests
 * are rounded up to one alignment unit. When the static arena has no room,
 * the function allocates from the heap and stores the block length in a
 * prefix used by alloc_free().
 *
 * Constraints:
 *   - @norig must be non-negative
 *
 * Security:
 *   - heap-backed allocations are wiped before first use
 */
void *alloc(long long norig) {

    unsigned char *x;
    unsigned long long i, n = norig;

    if (norig < 0) {
        log_e3("alloc(", log_num(norig), ") ... failed, < 0");
        goto inval;
    }
    if (n == 0) {
        log_t3("alloc(0), will allocate ", log_num(alloc_ALIGNMENT), " bytes");
        n = alloc_ALIGNMENT;
    }
    n = ((n + alloc_ALIGNMENT - 1) / alloc_ALIGNMENT) * alloc_ALIGNMENT;
    if (n <= avail) {
        avail -= n;
        log_t3("alloc(", log_num(norig), ") ... ok, static");
        return (void *) (space + avail);
    }

    n += alloc_ALIGNMENT;
    allocated += n;

    if (n != (unsigned long long) (size_t) n) {
        log_e3("alloc(", log_num(norig), ") ... failed, size_t overflow");
        goto nomem;
    }

    x = (unsigned char *) malloc(n);
    if (!x) {
        log_e3("alloc(", log_num(norig), ") ... failed, malloc() failed");
        goto nomem;
    }
    cleanup(x, n);

    for (i = 0; i < alloc_ALIGNMENT; ++i) {
        *x++ = n;
        n >>= 8;
    }

    if (!ptr_add(x)) {
        log_e3("alloc(", log_num(norig), ") ... failed, malloc() failed");
        goto nomem;
    }
    log_t5("alloc(", log_num(norig), ") ... ok, using malloc(), total ",
           log_num(allocated), " bytes");
    return (void *) x;
nomem:
    errno = ENOMEM;
    return (void *) 0;
inval:
    errno = EINVAL;
    return (void *) 0;
}

/*
 * alloc_free - release memory allocated by alloc
 *
 * @xv: pointer returned by alloc()
 *
 * Heap allocations are wiped and freed. Pointers into the static arena
 * are left untouched.
 */
void alloc_free(void *xv) {

    unsigned char *x = xv;
    unsigned long long i, n = 0;

    if (!x) {
        log_w1("alloc_free(0)");
        return;
    }

    if (x >= space)
        if (x < space + sizeof space) return;

    ptr_remove(x);

    for (i = 0; i < alloc_ALIGNMENT; ++i) {
        n <<= 8;
        n |= *--x;
    }

    cleanup(x, n);
    free(x);
}

/*
 * alloc_freeall - release all tracked heap allocations
 *
 * Wipes and frees every outstanding heap block and clears the static
 * arena used for small allocations.
 */
void alloc_freeall(void) {

    while (ptrlen > 0) { alloc_free(ptr[0]); }
    if (ptr) {
        free(ptr);
        ptr = 0;
        ptrlen = ptralloc = 0;
    }

    cleanup(space, sizeof space);
}
