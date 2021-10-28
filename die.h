#ifndef _DIE_H____
#define _DIE_H____

#include <unistd.h>
#include "log.h"

static void cleanup(void); /* callback */

#define die(x) { cleanup(); _exit(x); }

static void die_usage(const char *x) {

    log_u1(x);
    die(100);
}

static void die_fatal_(const char *fn, unsigned long long line, const char *trouble, const char *d, const char *f) {

    if (d) {
        if (f) log_9_(1, 1, fn, line, trouble, " ", d, "/", f, 0, 0, 0, 0);
        else log_9_(1, 1, fn, line, trouble, " ", d, 0, 0, 0, 0, 0, 0);
    }
    else {
        log_9_(1, 1, fn, line, trouble, 0, 0, 0, 0, 0, 0, 0, 0);
    }
    die(111);
}

#define die_fatal(a, b, c) die_fatal_(__FILE__, __LINE__, (a), (b), (c)) 

#endif
