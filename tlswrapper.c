/*
 * tlswrapper.c - dispatch a multi-call binary by argv[0]
 *
 * Provides the top-level entry point for the tlswrapper multi-call
 * executable. The binary selects the appropriate application mode from
 * its invoked program name and forwards execution to the corresponding
 * main_* implementation.
 */

#include <unistd.h>
#include "str.h"
#include "main.h"

/*
 * basename - return the final path component
 *
 * @str: mutable path string, or null
 *
 * Returns a pointer into @str that starts at the character after the last
 * '/'. If @str is null, the function returns null.
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
 * main - dispatch execution based on argv[0]
 *
 * @argc: process argument count
 * @argv: process argument vector
 *
 * Chooses the concrete tlswrapper mode from the invoked program name.
 * "tlswrapper-tcp" and "tlswrapper-smtp" are dispatched to their
 * dedicated entry points; all other names fall back to the generic
 * tlswrapper mode.
 *
 * Returns the selected subprogram's exit status.
 */
int main(int argc, char **argv) {

    if (argc < 1) _exit(100);
    if (!argv[0]) _exit(100);

    x = basename(argv[0]);
    if (!x) _exit(100);

    if (str_equal(x, "tlswrapper-tcp")) {
        return main_tlswrapper_tcp(argc, argv, 0);
    }
    if (str_equal(x, "tlswrapper-smtp")) {
        return main_tlswrapper_smtp(argc, argv, 0);
    }
    return main_tlswrapper(argc, argv, 0);

    _exit(111);
    return 111; /* make compiler happy */
}
