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

    if (!strcmp(x, "tlswrapper")) {
        return main_tlswrapper(argc, argv);
    }
    else if (!strcmp(x, "tlswrapper-tcpproxy")){
        return main_tlswrapper_tcpproxy(argc, argv);
    }
    else if (!strcmp(x, "tlswrapper-loadpem")){
        return main_tlswrapper_loadpem(argc, argv);
    }
    else {
        return main_tlswrapper(argc, argv);
    }

    _exit(111);
    return 111;
}
