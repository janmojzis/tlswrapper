/*
 * parseport.c - Parse decimal port numbers into 2-byte network order.
 *
 * This module parses a decimal TCP/UDP port number in the range <0,65535>.
 * The low-level parser returns 1/0; the public wrapper logs and sets errno on
 * error.
 */

#include "e.h"
#include "log.h"
#include "parsenum.h"
#include "parseport.h"

/*
 * parseport_ - Parse a numeric TCP/UDP port into a 2-byte big-endian buffer.
 *
 * @port: output buffer
 * @str: input string, NUL-terminated
 *
 * Parses a canonical unsigned decimal port number in the inclusive range
 * <0,65535> and stores it in network byte order. The accepted grammar is
 * 0|[1-9][0-9]* with no leading sign and no whitespace.
 *
 * Constraints:
 *   - port must be non-NULL
 *   - str must be non-NULL
 *   - port must point to at least 2 writable bytes
 *
 * Returns 1 on success, 0 on error.
 */
int parseport_(unsigned char *port, const char *str) {

    long long num;

    /* Reject NULL pointers */
    if (!port || !str) return 0;

    /* Reject empty string, leading '+' or '-' (ports are unsigned) */
    if (!str[0] || str[0] == '+' || str[0] == '-') return 0;

    /* Delegate numeric parsing to parsenum_(), range 0..65535 */
    if (!parsenum_(&num, 0, 65535, str)) return 0;

    /* Store as 2-byte big-endian (network byte order) */
    port[0] = (unsigned char) (num >> 8);
    port[1] = (unsigned char) (num);
    return 1;
}

/*
 * parseport - Parse a numeric TCP/UDP port into a 2-byte big-endian buffer.
 *
 * @port: output buffer
 * @str: input string, NUL-terminated
 *
 * Wrapper around parseport_() that adds errno handling and log messages.
 * Successful parses emit a tracing log and clear errno. Invalid input emits
 * a bug log for a NULL output pointer and an error log for malformed input.
 *
 * Constraints:
 *   - port must be non-NULL
 *   - port must point to at least 2 writable bytes
 *   - valid input strings match 0|[1-9][0-9]* and fall within <0,65535>
 *
 * Returns 1 on success, 0 on error. On error, errno is set to EINVAL.
 */
int parseport(unsigned char *port, const char *str) {

    if (!port) {
        errno = EINVAL;
        log_b1("parseport() called with port = (null)");
        return 0;
    }
    if (!str) goto err;
    if (!parseport_(port, str)) goto err;

    /* Success: clear errno and log the parsed value. */
    errno = 0;
    log_t4("'", log_str(str), "' parsed to ", log_port(port));
    return 1;

err:
    /* Failure: set errno and log an error. */
    errno = EINVAL;
    log_e3("'", log_str(str),
           "' is not a valid port number in the range <0,65535>");
    return 0;
}
