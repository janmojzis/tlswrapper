/*
 * fixpath.c - normalize untrusted path fragments in place
 *
 * Provides a small sanitizer for path strings derived from untrusted
 * input. The transformation removes repeated slashes after a slash and
 * rewrites "/." path components to "/:" so callers cannot traverse dot
 * entries inside restricted directory trees.
 */

#include "fixpath.h"

/*
 * fixpath - rewrite unsafe path components in place
 *
 * @s: mutable NUL-terminated path string
 *
 * Scans @s in place and normalizes characters that follow '/'. A literal
 * '.' after '/' is rewritten to ':', and repeated '/' characters after '/'
 * are dropped.
 *
 * Security:
 *   - Prevents "/." components from being interpreted as dot entries.
 *   - Collapses repeated '/' characters after '/'.
 */
void fixpath(char *s) {

    char ch;
    unsigned long long i, j;

    j = 0;
    for (i = 0; s[i]; ++i) {
        ch = s[i];
        if (j && (s[j - 1] == '/')) {
            if (ch == '.') ch = ':';
            if (ch == '/') continue;
        }
        s[j++] = ch;
    }
    s[j] = 0;
}
