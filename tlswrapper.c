/*
20181206
Jan Mojzis
Public domain.
*/

/*
Multi-call binary wrapper
*/

#include <unistd.h>
#include "str.h"
#include "main.h"

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

int main(int argc, char **argv) {

    if (argc < 1) _exit(100);
    if (!argv[0]) _exit(100);

    x = basename(argv[0]);
    if (!x) _exit(100);

    if (str_equal(x, "tlswrapper-tcp")) {
        return main_tlswrapper_tcp(argc, argv);
    }
    if (str_equal(x, "tlswrapper-smtp")) {
        return main_tlswrapper_smtp(argc, argv);
    }
    return main_tlswrapper(argc, argv, 0);

    _exit(111);
    return 111; /* make compiler happy */
}
