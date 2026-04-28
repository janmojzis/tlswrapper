/*
 * parsename.c - Parse DNS names into DNS wire format.
 *
 * This module converts dot-separated DNS names (presentation form) into DNS
 * wire format (length-prefixed labels ending in a zero-length root label). The
 * low-level parser returns 1/0; the public wrapper logs and sets errno on
 * error.
 *
 * SPDX-License-Identifier: MIT-0
 */

#include <errno.h>
#include "log.h"
#include "parsename.h"

/*
 * parsename_ - Parse a DNS name string into DNS wire format.
 * @out: output buffer (must be at least parsename_BYTES = 256 bytes)
 * @str: input DNS name string, NUL-terminated
 *       (e.g. "www.example.com")
 *
 * Converts a dot-separated DNS name into DNS wire format where each
 * label is prefixed by its length byte, terminated by a zero-length
 * label (root).
 *
 * Example: "www.example.com" ->
 * {3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0}
 *
 * Constraints enforced:
 *   - input must not be NULL
 *   - each label must be at most 63 bytes (DNS label limit)
 *   - total wire-format output must be at most 255 bytes (RFC 1035)
 *     (for common presentation forms this corresponds to at most 253
 *     characters excluding an optional trailing dot)
 *   - label characters must be ASCII [A-Za-z0-9_-]
 *     Note: '_' is accepted for compatibility with common DNS record owner
 *     names such as SRV/ACME/DKIM-style labels (e.g. "_sip._tcp",
 *     "_acme-challenge"). This is not a strict "hostname" validator.
 *   - labels must not start or end with a hyphen (RFC 952/1123 hostname rules)
 *   - empty labels (leading dot, consecutive dots) are rejected
 *
 * Returns 1 on success, 0 on error.
 * On success, out[0..N] contains the wire-format encoding (N <= 254).
 * The rest of the buffer (up to 256 bytes) is zero-filled.
 * Note: The last byte (index 255) is explicitly unused/empty: the maximum
 * wire-format length is 255 bytes, but the buffer is 256 bytes.
 */
int parsename_(unsigned char *out, const char *str) {

    long long pos;
    long long j;
    long long i;
    unsigned char c;

    /* Reject NULL pointers. */
    if (!out || !str) return 0;

    /* Reject empty labels: leading dot or consecutive dots. */
    if (str[0] == '.' && str[1] != 0) return 0;
    for (i = 0; str[i]; ++i)
        if (str[i] == '.' && str[i + 1] == '.') return 0;

    /* Zero-fill the entire output buffer. */
    for (pos = 0; pos < 256; ++pos) out[pos] = 0;

    pos = 0;
    while (*str) {
        /* Skip trailing dot (FQDN notation). */
        if (*str == '.') {
            ++str;
            continue;
        }

        /* Measure the current label: count bytes until next dot or end of
         * string */
        for (j = 0; str[j]; ++j)
            if (str[j] == '.') break;

        /* Reject label longer than 63 bytes (DNS protocol limit). */
        if (j > 63) return 0;

        /* Validate label characters.
         *
         * We accept ASCII [A-Za-z0-9_-]. Underscore is intentionally allowed
         * for compatibility with common DNS record owner names such as SRV,
         * ACME (e.g. "_sip._tcp", "_acme-challenge").
         */
        for (i = 0; i < j; ++i) {
            c = (unsigned char) str[i];
            if (c >= 'a' && c <= 'z') continue;
            if (c >= 'A' && c <= 'Z') continue;
            if (c >= '0' && c <= '9') continue;
            if (c == '-' || c == '_') continue;
            return 0;
        }

        /* Reject label starting or ending with hyphen (RFC 952/1123). */
        if (str[0] == '-') return 0;
        if (str[j - 1] == '-') return 0;

        /* Write label length byte; check for wire-format overflow (max 255
         * bytes) */
        if (pos < 0 || pos >= 255) return 0;
        out[pos++] = (unsigned char) j;

        /* Copy label bytes into output; check overflow on each byte. */
        while (j > 0) {
            if (pos < 0 || pos >= 255) return 0;
            out[pos++] = (unsigned char) *str++;
            --j;
        }
    }

    /* Write terminating zero-length label (root); check overflow. */
    if (pos < 0 || pos >= 255) return 0;
    out[pos++] = 0;
    return 1;
}

/*
 * parsename - Parse a DNS name string into DNS wire format with logging.
 * @out: output buffer (must be at least parsename_BYTES = 256 bytes, must not
 *       be NULL; the last byte is explicitly unused/empty)
 * @str: input DNS name string, NUL-terminated
 *
 * Wrapper around parsename_() that adds NULL-pointer checks, errno handling,
 * and log messages (tracing on success, error on failure).
 * Returns 1 on success, 0 on error (errno set to EINVAL).
 */
int parsename(unsigned char *out, const char *str) {

    if (!out) {
        errno = EINVAL;
        log_b1("parsename() called with out = (null)");
        return 0;
    }
    if (!str) goto err;
    if (!parsename_(out, str)) goto err;

    /* Success: clear errno and log the parsed name. */
    errno = 0;
    log_t3("'", log_str(str), "' parsed as a valid DNS name");
    return 1;

err:
    /* Failure: set errno and log an error. */
    errno = EINVAL;
    log_e3("'", log_str(str), "' is not a valid DNS name");
    return 0;
}
