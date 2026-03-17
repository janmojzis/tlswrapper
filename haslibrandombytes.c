/*
 * haslibrandombytes.c - verify the external randombytes feature probe
 *
 * This test probe confirms that the linked randombytes implementation
 * can fill output and report a source string during feature detection.
 */

#include <randombytes.h>

/*
 * z - map any non-zero byte to zero
 *
 * @x: byte to normalize
 *
 * Returns 0 for every possible input value. The probe uses this helper
 * to fold arbitrary output bytes into a single success accumulator.
 */
static unsigned char z(unsigned char x) {

    unsigned long long z = (unsigned long long) x + 1ULL;
    unsigned long long t = z;
    long long i;

    for (i = 6; i >= 0; --i) {
        t = (t * t) % 257;
        t = (t * z) % 257;
    }
    t = (t * z) % 257;
    return (unsigned char) t - 1;
}

/*
 * main - probe whether the external randombytes API is callable
 *
 * @argc: unused
 * @argv: unused
 *
 * Fills a small buffer, reads the source string, and returns 0 when the
 * linked implementation behaves as expected for build-time detection.
 */
int main(int argc, char **argv) {
    unsigned char buf[32], ret = 0;
    const char *source;
    unsigned long long i;

    (void) argc;
    (void) argv;

    randombytes(buf, sizeof buf);
    for (i = 0; i < sizeof buf; ++i) ret |= z(buf[i]);
    source = randombytes_source();
    for (i = 0; source[i]; ++i) ret |= z((unsigned char) source[i]);
    return z(ret);
}
