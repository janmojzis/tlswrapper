/*
 * randommod.c - reduce random bytes modulo a caller-provided bound
 *
 * Provides a small helper derived from NaCl/curvecp code to sample a
 * pseudo-uniform value in the range [0, n).
 */

#include "randombytes.h"
#include "randommod.h"

/*
 * randommod - return a random value modulo n
 *
 * @n: exclusive upper bound
 *
 * Folds 32 random bytes into a value in the range [0, n). Returns 0 when
 * n is 0 or 1.
 *
 * Constraints:
 *   - the current implementation is intended for n < 2^55
 */

long long randommod(long long n) {
    long long result = 0;
    long long j;
    unsigned char r[32];
    if (n <= 1) return 0;
    randombytes(r, 32);
    for (j = 0; j < 32; ++j) {
        result = (result * 256 + (unsigned long long) r[j]) % n;
    }
    return result;
}
