#include <string.h>
#include <arpa/inet.h>
#include "strtoip.h"

int strtoip4(unsigned char *ip, const char *x) {

    if (!x) return 0;
    if (inet_pton(AF_INET, x, ip + 12) != 1) return 0;
         memcpy(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
    return 1;
}

int strtoip6(unsigned char *ip, const char *x) {

    if (!x) return 0;
    if (inet_pton(AF_INET6, x, ip) != 1) return 0;
    return 1;
}

int strtoip(unsigned char *ip, const char *x) {

    if (strtoip4(ip, x)) return 1;
    if (strtoip6(ip, x)) return 1;
    return 0;
}
