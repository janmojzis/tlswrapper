/*
 * tlswrapper-test.c - dispatch the multicall tlswrapper test binary
 *
 * This module selects the requested tlswrapper test frontend from
 * argv[0] so one executable can provide several entry points.
 */

#include <unistd.h>
#include "str.h"
#include "main.h"

/*
 * basename - return the last path component
 *
 * @str: mutable path string
 *
 * Returns a pointer inside @str to the final component after the last
 * slash. Null input is returned unchanged.
 */
static char *basename(char *str) {

    char *s;
    char *ret = str;

    if (!str) return str;

    for (s = str; *s; ++s) {
        if (*s == '/') ret = s + 1;
    }
    return ret;
}

static char *x;

/*
 * main - dispatch to the selected tlswrapper frontend
 *
 * @argc: process argument count
 * @argv: process argument vector
 *
 * Examines argv[0] and calls the matching frontend implementation.
 * Unknown names fall back to the test harness entry point.
 */
int main(int argc, char **argv) {

    if (argc < 1) _exit(100);
    if (!argv[0]) _exit(100);

    x = basename(argv[0]);
    if (!x) _exit(100);

    if (str_equal(x, "tlswrappernojail")) {
        return main_tlswrapper(argc, argv, 1);
    }
    if (str_equal(x, "tlswrappernojail-tcp")) {
        return main_tlswrapper_tcp(argc, argv, 1);
    }
    if (str_equal(x, "tlswrappernojail-smtp")) {
        return main_tlswrapper_smtp(argc, argv, 1);
    }
    return main_tlswrapper_test(argc, argv);

    _exit(111);
    return 111; /* make compiler happy */
}
