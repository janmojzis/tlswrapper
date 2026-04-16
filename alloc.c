/*
 * alloc.c - memory allocator with tracked cleanup
 *
 * This module provides zero-initialized memory allocations.
 * Every allocation is tracked in a small linked list so callers can
 * wipe individual blocks and reset all outstanding allocations.
 */

#include "alloc.h"
#include "log.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

struct alloc_node {
    void *ptr;
    long long len;
    struct alloc_node *next;
};

static unsigned char space[alloc_STATICSPACE]
    __attribute__((aligned(alloc_ALIGNMENT)));
static unsigned long long avail = sizeof space;
static long long allocated = 0;
static struct alloc_node *alloc_head = 0;

/*
 * alloc_aligned_len - compute the backing size for a logical length
 *
 * @len: logical allocation length in bytes
 *
 * Returns the aligned backing allocation size used by alloc().
 */
static unsigned long long alloc_aligned_len(long long len) {

    unsigned long long n;

    if (len <= 0) return (unsigned long long) alloc_ALIGNMENT;

    n = (unsigned long long) len;
    return ((n + alloc_ALIGNMENT - 1) / alloc_ALIGNMENT) * alloc_ALIGNMENT;
}

/*
 * alloc_is_static - test whether a pointer is inside the static arena
 *
 * @ptr: pointer returned by alloc()
 *
 * Returns 1 when @ptr points into the static allocation buffer.
 */
static int alloc_is_static(const void *ptr) {

    uintptr_t start = (uintptr_t) space;
    uintptr_t end = start + sizeof space;
    uintptr_t p = (uintptr_t) ptr;

    return p >= start && p < end;
}

/*
 * cleanup - wipe a buffer through a volatile machine-word view
 *
 * @xv: buffer to clear
 * @xlen: buffer size in bytes
 *
 * Clears the whole buffer in machine-word chunks. This is safe because
 * alloc_ALIGNMENT is a whole-number multiple of machine-word size, and
 * cleanup() is only used with lengths rounded to alloc_ALIGNMENT or
 * with other machine-word-sized buffers. Uses an asm barrier to keep
 * the writes from being optimized away.
 *
 * Constraints:
 *   - @xv must point to storage that is machine-word aligned
 *   - @xlen must be a whole-number multiple of machine-word size
 *
 * Security:
 *   - attempts to preserve the memory wipe
 */
static void cleanup(void *xv, unsigned long long xlen) {

    volatile unsigned long *x = (volatile unsigned long *) xv;

    xlen /= sizeof(*x);
    while (xlen-- > 0) *x++ = 0;

#ifdef __GNUC__
    __asm__ __volatile__("" : : "r"(xv) : "memory");
#endif
}

/*
 * alloc_add - track a memory allocation
 *
 * @ptr: allocation returned to the caller
 * @len: requested allocation size in bytes
 *
 * Returns 1 on success, 0 on failure.
 */
static int alloc_add(void *ptr, long long len) {

    struct alloc_node *node;

    node = (struct alloc_node *) malloc(sizeof(*node));
    if (!node) return 0;
    node->ptr = ptr;
    node->len = len;
    node->next = alloc_head;
    alloc_head = node;
    return 1;
}

/*
 * alloc_remove - detach a tracked allocation
 *
 * @ptr: allocation to remove from the tracker
 *
 * Returns the detached node when @ptr is present, 0 when not found.
 */
static struct alloc_node *alloc_remove(void *ptr) {

    struct alloc_node *prev = 0;
    struct alloc_node *node = alloc_head;

    while (node) {
        if (node->ptr == ptr) {
            if (prev)
                prev->next = node->next;
            else
                alloc_head = node->next;
            return node;
        }
        prev = node;
        node = node->next;
    }
    return 0;
}

/*
 * alloc - allocate zero-initialized memory storage
 *
 * @norig: requested allocation size in bytes
 *
 * Returns memory storage for at least @norig bytes. Zero-length requests
 * are rounded up to alloc_ALIGNMENT so the result can still be passed
 * to alloc_free().
 *
 * Constraints:
 *   - @norig must be non-negative
 *
 * Security:
 *   - returned memory is zero-initialized
 */
void *alloc(long long norig) {

    unsigned char *x;
    unsigned long long n;

    if (norig < 0) {
        errno = EINVAL;
        log_e3("alloc(", log_num(norig), ") ... failed, requested length < 0");
        return (void *) 0;
    }
    /*
     * Check for signed integer overflow before rounding the requested
     * length up to alloc_ALIGNMENT.
     */
    if ((unsigned long long) norig >
        ((((unsigned long long) (-1)) >> 1) - (alloc_ALIGNMENT - 1))) {
        errno = ENOMEM;
        log_e3("alloc(", log_num(norig),
               ") ... failed, too large to align safely");
        return (void *) 0;
    }

    if (norig == 0) {
        log_t3("alloc(0), will round up to ", log_num(alloc_ALIGNMENT),
               " bytes");
    }

    n = alloc_aligned_len(norig);
    if (n <= avail) {
        avail -= n;
        errno = 0;
        log_t3("alloc(", log_num(norig), ") ... ok, static");
        return (void *) (space + avail);
    }

    if ((unsigned long long) allocated + (unsigned long long) norig >
        alloc_MAX) {
        errno = ENOMEM;
        log_e5("alloc(", log_num(norig),
               ") ... failed, allocation limit ",
               log_num((long long) alloc_MAX), "B reached");
        return (void *) 0;
    }

    if ((unsigned long long) (size_t) n != n) {
        errno = ENOMEM;
        log_e3("alloc(", log_num(norig),
               ") ... failed, requested length does not fit in size_t");
        return (void *) 0;
    }

    x = (unsigned char *) malloc((size_t) n);
    if (!x) {
        errno = ENOMEM;
        log_e3("alloc(", log_num(norig), ") ... failed, malloc() returned 0");
        return (void *) 0;
    }
    cleanup(x, n);

    if (!alloc_add(x, norig)) {
        cleanup(x, n);
        free(x);
        errno = ENOMEM;
        log_e3("alloc(", log_num(norig),
               ") ... failed, allocation tracking failed");
        return (void *) 0;
    }

    allocated += norig;
    errno = 0;
    log_t5("alloc(", log_num(norig), ") ... ok, using malloc(), total ",
           log_num(allocated), " bytes");
    return x;
}

/*
 * alloc_free - wipe and detach memory allocated by alloc
 *
 * @xv: pointer returned by alloc()
 *
 * Memory allocations are wiped using their tracked logical length and
 * then detached from the allocator state. Heap-backed blocks are freed
 * immediately. Static-arena blocks remain unavailable until
 * alloc_freeall() resets the arena.
 */
void alloc_free(void *xv) {

    struct alloc_node *node;
    unsigned long long n;

    if (!xv) {
        log_t1("alloc_free(0)");
        return;
    }
    if (alloc_is_static(xv)) return;

    node = alloc_remove(xv);
    if (!node) {
        log_b1("alloc_free() called for untracked pointer");
        return;
    }

    n = alloc_aligned_len(node->len);
    allocated -= node->len;
    cleanup(xv, n);
    free(xv);
    free(node);
}

/*
 * alloc_freeall - release all tracked memory allocations
 *
 * Wipes and frees every outstanding memory block.
 */
void alloc_freeall(void) {

    struct alloc_node *node = alloc_head;
    struct alloc_node *next;

    alloc_head = 0;
    while (node) {
        next = node->next;
        cleanup(node->ptr, alloc_aligned_len(node->len));
        free(node->ptr);
        free(node);
        node = next;
    }

    cleanup(space, sizeof space);
    avail = sizeof space;
    allocated = 0;
}
