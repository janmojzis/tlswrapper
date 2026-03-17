/*
 * milliseconds.c - return wall-clock time in milliseconds
 */

#include <time.h>
#include <sys/time.h>
#include "milliseconds.h"

/*
 * milliseconds - read the current time in milliseconds
 *
 * Returns the current gettimeofday() value converted to a millisecond
 * count since the Unix epoch.
 */
long long milliseconds(void) {

    struct timeval t;
    gettimeofday(&t, (struct timezone *) 0);
    return t.tv_sec * 1000LL + t.tv_usec / 1000LL;
}
