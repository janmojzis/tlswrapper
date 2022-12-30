#include "fixpath.h"

/* for security reasons the 'fixpath(s)' function replaces '/.' -> '/:' */

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
