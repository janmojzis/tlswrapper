/*
 * case.c - ASCII-only case-insensitive string helpers
 *
 * This module provides comparisons, prefix checks, and lowercase
 * conversions for ASCII text used throughout the codebase.
 *
 * version 20220221
 */

#include "case.h"

/*
 * case_diffb - compare fixed-length strings case-insensitively
 *
 * @s: first byte string
 * @len: number of bytes to compare
 * @t: second byte string
 *
 * Returns the first ASCII case-insensitive byte difference, or 0 when
 * the first @len bytes match.
 */
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

/*
 * case_diffs - compare NUL-terminated strings case-insensitively
 *
 * @s: first string
 * @t: second string
 *
 * Returns the first ASCII case-insensitive character difference, or 0
 * when both strings are equal.
 */
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

/*
 * case_startb - test a fixed-length prefix case-insensitively
 *
 * @s: candidate buffer
 * @len: available bytes in @s
 * @t: NUL-terminated prefix
 *
 * Returns 1 when @t matches the start of @s within @len bytes.
 */
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

/*
 * case_starts - test a string prefix case-insensitively
 *
 * @s: candidate string
 * @t: NUL-terminated prefix
 *
 * Returns 1 when @t matches the beginning of @s.
 */
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

/*
 * case_lowerb - lowercase a fixed-length ASCII buffer
 *
 * @s: buffer to modify in place
 * @len: number of bytes to process
 *
 * Converts ASCII uppercase letters to lowercase and leaves other bytes
 * unchanged.
 */
void case_lowerb(char *s, long long len) {

    unsigned char x;

    while (len > 0) {
        --len;
        x = *s - 'A';
        if (x <= 'Z' - 'A') *s = x + 'a';
        ++s;
    }
}

/*
 * case_lowers - lowercase a NUL-terminated ASCII string
 *
 * @s: string to modify in place
 *
 * Converts ASCII uppercase letters until the terminating NUL byte.
 */
void case_lowers(char *s) {

    unsigned char x;

    while ((x = *s)) {
        x -= 'A';
        if (x <= 'Z' - 'A') *s = x + 'a';
        ++s;
    }
}
