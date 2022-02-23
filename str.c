/*
version 20220222
*/

#include "str.h"

/*
The 'str_len(s)' function calculates the length of the string 's'.
*/
long long str_len(const char *s) {

    long long i;

    for (i = 0; s[i]; ++i)
        ;
    return i;
}

/*
The 'str_start(s,t)' function returns 1 if 't' is a prefix of 's', 0 otherwise.
*/
int str_start(const char *s, const char *t) {

    long long i;

    for (i = 0; s[i]; ++i) {
        if (s[i] != t[i]) break;
    }
    return (t[i] == 0);
}

/*
The 'str_chr(s,c)' function returns a position to the first occurrence of the
character 'c' in the string 's'. Or a position to the '\0' termination character
if the character 'c' is not found.
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
The 'str_rchr(s,c)' function returns a position to the last occurrence of the
character 'c' in the string 's'. Or a position to the '\0' termination character
if the character 'c' is not found.
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
The 'str_diff(s,t)' function returns an integer greater than, equal to, or less
than 0, according as the string 's' is greater than, equal to, or less than the
string 't'.
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
The 'str_diffn(s,t,len)' function returns an integer greater than, equal to, or
less than 0, according as the string 's' is greater than, equal to, or less than
the string 't'. But compares not more than 'len' characters.
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
The 'str_copy(s,t) function copies the string 't' to 's' including the
terminating ‘\0’ character and returns the length of the string.
*/
long long str_copy(char *s, const char *t) {

    long long i;

    for (i = 0; t[i]; ++i) s[i] = t[i];
    s[i] = 0;
    return i;
}
