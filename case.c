/*
version 20220221
*/

#include "case.h"

int case_diffb(const char *s, long long len, const char *t) {

    unsigned char x, y;

    while (len > 0) {
        --len;
        x = *s++ - 'A';
        if (x <= 'Z' - 'A')
            x += 'a';
        else
            x += 'A';
        y = *t++ - 'A';
        if (y <= 'Z' - 'A')
            y += 'a';
        else
            y += 'A';
        if (x != y) return ((int) (unsigned int) x) - ((int) (unsigned int) y);
    }
    return 0;
}

int case_diffs(const char *s, const char *t) {

    unsigned char x, y;

    for (;;) {
        x = *s++ - 'A';
        if (x <= 'Z' - 'A')
            x += 'a';
        else
            x += 'A';
        y = *t++ - 'A';
        if (y <= 'Z' - 'A')
            y += 'a';
        else
            y += 'A';
        if (x != y) break;
        if (!x) break;
    }
    return ((int) (unsigned int) x) - ((int) (unsigned int) y);
}

int case_startb(const char *s, long long len, const char *t) {

    unsigned char x, y;

    for (;;) {
        y = *t++ - 'A';
        if (y <= 'Z' - 'A')
            y += 'a';
        else
            y += 'A';
        if (!y) return 1;
        if (!len) return 0;
        --len;
        x = *s++ - 'A';
        if (x <= 'Z' - 'A')
            x += 'a';
        else
            x += 'A';
        if (x != y) return 0;
    }
}

int case_starts(const char *s, const char *t) {

    unsigned char x, y;

    for (;;) {
        x = *s++ - 'A';
        if (x <= 'Z' - 'A')
            x += 'a';
        else
            x += 'A';
        y = *t++ - 'A';
        if (y <= 'Z' - 'A')
            y += 'a';
        else
            y += 'A';
        if (!y) return 1;
        if (x != y) return 0;
    }
}

void case_lowerb(char *s, long long len) {

    unsigned char x;

    while (len > 0) {
        --len;
        x = *s - 'A';
        if (x <= 'Z' - 'A') *s = x + 'a';
        ++s;
    }
}

void case_lowers(char *s) {

    unsigned char x;

    while ((x = *s)) {
        x -= 'A';
        if (x <= 'Z' - 'A') *s = x + 'a';
        ++s;
    }
}
