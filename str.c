/*
 * str.c - simple string helpers for NUL-terminated ASCII data
 *
 * Provides length, prefix, search, compare, and copy helpers used by the
 * rest of the codebase without depending on libc string routines.
 */

#include "str.h"

/*
 * str_len - return the length of a NUL-terminated string
 *
 * @s: input string
 *
 * Counts bytes until the first terminating NUL byte.
 */
long long str_len(const char *s) {

    long long i;

    for (i = 0; s[i]; ++i);
    return i;
}

/*
 * str_start - test whether one string starts with another
 *
 * @s: candidate string
 * @t: prefix string
 *
 * Returns 1 when t is a prefix of s and 0 otherwise.
 */
int str_start(const char *s, const char *t) {

    long long i;

    for (i = 0; s[i]; ++i) {
        if (s[i] != t[i]) break;
    }
    return (t[i] == 0);
}

/*
 * str_chr - find the first matching byte in a string
 *
 * @s: input string
 * @c: byte value to search for
 *
 * Returns the index of the first matching byte, or the index of the
 * terminating NUL byte when c does not occur earlier.
 */
long long str_chr(const char *s, int c) {

    long long i;
    char ch = c;

    for (i = 0; s[i]; ++i) {
        if (s[i] == ch) break;
    }
    return i;
}

/*
 * str_rchr - find the last matching byte in a string
 *
 * @s: input string
 * @c: byte value to search for
 *
 * Returns the index of the last matching byte, or the index of the
 * terminating NUL byte when c does not occur.
 */
long long str_rchr(const char *s, int c) {

    long long i, u = -1;
    char ch = c;

    for (i = 0; s[i]; ++i) {
        if (s[i] == ch) u = i;
    }
    if (u != -1) return u;
    return i;
}

/*
 * str_diff - compare two NUL-terminated strings
 *
 * @s: first string
 * @t: second string
 *
 * Returns a negative, zero, or positive value according to the first byte
 * difference between s and t.
 */
int str_diff(const char *s, const char *t) {

    long long i;

    for (i = 0; s[i]; ++i) {
        if (s[i] != t[i]) break;
    }
    return ((int) (unsigned int) (unsigned char) s[i]) -
           ((int) (unsigned int) (unsigned char) t[i]);
}

/*
 * str_diffn - compare two strings up to a byte limit
 *
 * @s: first string
 * @t: second string
 * @len: maximum number of bytes to compare
 *
 * Returns a negative, zero, or positive value according to the first byte
 * difference within the compared prefix. Returns 0 when the first len
 * bytes match.
 */
int str_diffn(const char *s, const char *t, long long len) {

    long long i;

    for (i = 0; s[i]; ++i) {
        if (i >= len) return 0;
        if (s[i] != t[i]) break;
    }
    return ((int) (unsigned int) (unsigned char) s[i]) -
           ((int) (unsigned int) (unsigned char) t[i]);
}

/*
 * str_copy - copy a NUL-terminated string
 *
 * @s: destination buffer
 * @t: source string
 *
 * Copies t to s including the terminating NUL byte and returns the source
 * string length excluding that terminator.
 */
long long str_copy(char *s, const char *t) {

    long long i;

    for (i = 0; t[i]; ++i) s[i] = t[i];
    s[i] = 0;
    return i;
}
