/*
 * fixname.c - trim local account names at the domain separator
 *
 * Provides a small in-place helper for reducing names such as email-style
 * identities to their local part before they are matched against local
 * account or profile names.
 */

#include "fixname.h"

/*
 * fixname - keep only the part before '@'
 *
 * @x: mutable NUL-terminated name string
 *
 * Rewrites @x in place by truncating the string at the first '@'
 * character. Strings without '@' are left unchanged.
 */
void fixname(char *x) {

    long long i;

    for (i = 0; x[i]; ++i) {
        if (x[i] == '@') {
            x[i] = 0;
            break;
        }
    }
}
