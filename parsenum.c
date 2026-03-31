/*
 * parsenum.c - Parse signed integers within a specified range.
 *
 * This module parses a canonical signed decimal integer and validates it
 * against an inclusive range. Leading zeros are rejected except for the
 * single-digit value 0. The low-level parser returns 1/0; the public wrapper
 * logs and sets errno on error.
 */

#include "e.h"
#include "log.h"
#include "parsenum.h"

/*
 * parsenum_ - Parse a signed integer within a given range.
 *
 * @num: output parsed number; NULL is rejected
 * @min: inclusive minimum allowed value
 * @max: inclusive maximum allowed value
 * @str: input string, NUL-terminated; grammar:
 *       [+-]?(0|[1-9][0-9]*) (no whitespace)
 *
 * Returns 1 on success, 0 on error.
 * On error, *num is set to 0 when @num is non-NULL.
 *
 * Constraints:
 *   - @min must be less than or equal to @max for any input to succeed
 */
int parsenum_(long long *num, long long min, long long max, const char *str) {

    int flagsign = 0;
    long long i;
    unsigned long long c, ret = 0;

    if (!num || !str) goto err;

    /* Handle optional leading sign: first char can be +, -, or digit. */
    switch (str[0]) {
        case 0:
            /* empty string */
            goto err;
        case '+':
            /* skip +, treat as positive */
            ++str;
            break;
        case '-':
            /* skip -, remember negative */
            flagsign = 1;
            ++str;
            break;
        default:
            break; /* no sign */
    }

    /* Reject leading zeros (e.g. "007", "00082") but allow bare "0" */
    if (str[0] == '0' && str[1] != 0) goto err;

    /* Parse digits: accumulate value digit by digit */
    for (i = 0; str[i]; ++i) {
        c = (unsigned long long) (str[i] - '0');
        if (c > 9) goto err; /* character not in [0-9] */

        /* Accumulate: ret = ret * 10 + digit, with overflow check */
        if (ret > (((unsigned long long) (-1)) - c) / 10) goto err;
        ret = 10 * ret + c;
    }

    /* Must have at least one digit after optional sign */
    if (i == 0) goto err; /* only sign, no digits (e.g., "+" or "-") */

    /* Apply sign and check for signed overflow */
    if (flagsign) {
        if (ret > ((unsigned long long) parsenum_MAX) + 1) goto err;
        if (ret == ((unsigned long long) parsenum_MAX) + 1) {
            /* Preserve parsenum_MIN without negating a signed 2^63 value. */
            *num = parsenum_MIN;
        }
        else {
            *num = -(long long) ret;
        }
    }
    else {
        if (ret > ((unsigned long long) parsenum_MAX)) goto err;
        /* The remaining magnitude fits in signed long long. */
        *num = (long long) ret;
    }

    /* Validate result is within specified range */
    if (*num < min) goto err;
    if (*num > max) goto err;
    return 1;

err:
    /* On error: zero output, return failure */
    if (num) *num = 0;
    return 0;
}

/*
 * parsenum - Parse a signed integer within a given range with logging.
 *
 * @num: output parsed number (must be non-NULL)
 * @min: inclusive minimum allowed value
 * @max: inclusive maximum allowed value
 * @str: input string, NUL-terminated; grammar:
 *       [+-]?(0|[1-9][0-9]*) (no whitespace)
 *
 * Returns 1 on success (errno set to 0), 0 on error (errno set to EINVAL,
 * *num set to 0).
 * Logs a tracing message on success and an error on failure.
 *
 * Constraints:
 *   - @min must be less than or equal to @max for any input to succeed
 */
int parsenum(long long *num, long long min, long long max, const char *str) {

    if (!num) {
        errno = EINVAL;
        log_b1("parsenum() called with num = (null)");
        return 0;
    }
    if (!str) goto err;
    if (!parsenum_(num, min, max, str)) goto err;

    /* Success: clear errno and log the parsed value. */
    errno = 0;
    log_t4("'", log_str(str), "' parsed to ", log_num(*num));
    return 1;

err:
    /* Failure: zero output, set errno and log an error with range info. */
    if (num) *num = 0;
    errno = EINVAL;
    log_e7("'", log_str(str), "' is not a valid number in the range <",
           log_num(min), ",", log_num(max), ">");
    return 0;
}
