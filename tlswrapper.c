/*
20181206
Jan Mojzis
Public domain.
*/

/*
Multi-call binary wrapper
*/

#include <unistd.h>
#include <string.h>
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

    if (!strcmp(x, "tlswrapper-tcp")){
        return main_tlswrapper_tcp(argc, argv);
    }
    if (!strcmp(x, "tlswrapper-loadpem")){
        return main_tlswrapper_loadpem(argc, argv);
    }
    if (!strcmp(x, "tlswrapper-parseasn1")){
        return main_tlswrapper_parseasn1(argc, argv);
    }
    return main_tlswrapper(argc, argv);

    _exit(111);
    return 111; /* make compiler happy */
}
