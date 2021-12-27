#include "tls.h"

#define X(k, s)                                                                \
    if ((i) == (k)) return s;

const char *tls_keytype_str(int i) {
    X(BR_KEYTYPE_RSA, "RSA");
    X(BR_KEYTYPE_EC, "EC");
    return "UNKNOWN";
}
