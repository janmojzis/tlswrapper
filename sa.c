#include <string.h>
#include "alloc.h"
#include "sa.h"

void sa_append(void *sav, const void *bufv, unsigned long long buflen) {

    struct sa *sa = sav;
    const unsigned char *buf = bufv;
    unsigned char *newp;

    if (sa->alloc <= sa->len + buflen) {
        while (sa->alloc <= sa->len + buflen) {
            sa->alloc = 2 * sa->alloc + 1;
        }
        newp = alloc(sa->alloc);
        if (!newp) {
            sa->error = 1;
            return;
        }
        if (sa->p) {
            memcpy(newp, sa->p, sa->len);
            alloc_free(sa->p);
        }
        sa->p = newp;
    }

    memcpy(sa->p + sa->len, buf, buflen);
    sa->len += buflen;
}
