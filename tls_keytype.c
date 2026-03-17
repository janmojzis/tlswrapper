/*
 * tls_keytype.c - map BearSSL key type ids to short strings
 *
 * This module provides the small string table used in diagnostics and
 * certificate parsing logs.
 */

#include "tls.h"

#define X(k, s)                                                                \
    if ((i) == (k)) return s;

/*
 * tls_keytype_str - return the short name for a BearSSL key type
 *
 * @i: BearSSL key type identifier
 *
 * Returns a static string for known key types and "UNKNOWN" otherwise.
 */
const char *tls_keytype_str(int i) {
    X(BR_KEYTYPE_RSA, "RSA");
    X(BR_KEYTYPE_EC, "EC");
    return "UNKNOWN";
}
