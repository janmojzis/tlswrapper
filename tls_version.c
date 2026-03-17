/*
 * tls_version.c - map configured protocol version names to BearSSL ids
 *
 * This module provides the version table used for configuration parsing
 * and diagnostic strings.
 */

#include "str.h"
#include "tls.h"

/* clang-format off */
const tls_version tls_versions[] = {
    { "tls10", BR_TLS10, "TLS 1.0" },
    { "tls11", BR_TLS11, "TLS 1.1" },
    { "tls12", BR_TLS12, "TLS 1.2" },
    { 0, 0, 0 }
};
/* clang-format on */

/*
 * tls_version_str - return the display string for a TLS version id
 *
 * @version: BearSSL protocol version identifier
 *
 * Returns a static description from the local version table.
 */
const char *tls_version_str(unsigned int version) {

    long long i;

    for (i = 0; tls_versions[i].name; ++i) {
        if (tls_versions[i].version == version) return tls_versions[i].comment;
    }
    return "unknown version";
}

unsigned int tls_version_min = BR_TLS12;

/*
 * tls_version_setmin - set the configured minimum TLS version
 *
 * @ctx: TLS context to update
 * @x: configured version name
 *
 * Resolves @x in the local version table and stores the resulting minimum
 * protocol version in @ctx.
 */
int tls_version_setmin(struct tls_context *ctx, const char *x) {

    long long i;

    for (i = 0; tls_versions[i].name; ++i) {
        if (str_equal(x, tls_versions[i].name)) {
            ctx->version_min = tls_versions[i].version;
            return 1;
        }
    }
    return 0;
}

unsigned int tls_version_max = BR_TLS12;

/*
 * tls_version_setmax - set the configured maximum TLS version
 *
 * @ctx: TLS context to update
 * @x: configured version name
 *
 * Resolves @x in the local version table and stores the resulting maximum
 * protocol version in @ctx.
 */
int tls_version_setmax(struct tls_context *ctx, const char *x) {

    long long i;

    for (i = 0; tls_versions[i].name; ++i) {
        if (str_equal(x, tls_versions[i].name)) {
            ctx->version_max = tls_versions[i].version;
            return 1;
        }
    }
    return 0;
}
