/*
 * tls_ecdhe.c - configure supported ECDHE curves
 *
 * This module maps curve names to BearSSL identifiers and prepares a
 * customized EC implementation table. The customized table restricts the
 * enabled curves and routes scalar multiplication through the keyjail pipe.
 */

#include "str.h"
#include "tls.h"

/* clang-format off */
const tls_ecdhe tls_ecdhes[] = {
    { "x25519", tls_ecdhe_X25519 },
    { "secp256r1", tls_ecdhe_SECP256R1 },
    { "secp384r1", tls_ecdhe_SECP384R1 },
    { "secp521r1", tls_ecdhe_SECP521R1 },
#ifdef X448
    { "x448", tls_ecdhe_X448 },
#endif
    { 0, 0 }
};
/* clang-format on */

/*
 * tls_ecdhe_str - return the configuration name for a curve id
 *
 * @curve: BearSSL curve identifier
 *
 * Returns the configured curve name or "unknown" when the identifier is
 * not present in the local table.
 */
const char *tls_ecdhe_str(unsigned char curve) {

    long long i;

    for (i = 0; tls_ecdhes[i].name; ++i) {
        if (tls_ecdhes[i].curve == curve) return tls_ecdhes[i].name;
    }
    return "unknown";
}

static int use_default = 1;

/*
 * tls_ecdhe_add - enable an ECDHE curve by configuration name
 *
 * @ctx: TLS context to update
 * @x: configured curve name
 *
 * Enables the named curve in the context bitmask. The first explicit add
 * clears the default bitmask before applying user selections.
 */
int tls_ecdhe_add(struct tls_context *ctx, const char *x) {

    size_t i;

    if (use_default == 1) {
        ctx->ecdhe_enabled = 0;
        use_default = 0;
    }

    for (i = 0; tls_ecdhes[i].name; ++i) {
        if (str_diff(x, tls_ecdhes[i].name)) continue;
        ctx->ecdhe_enabled |= (uint32_t) 1 << tls_ecdhes[i].curve;
        return 1;
    }

    return 0;
}

static const br_ec_impl *ecdhe_orig;

/*
 * xoff - report the x-coordinate offset for a curve encoding
 *
 * @curve: BearSSL curve identifier
 * @len: returns the x-coordinate length
 *
 * Delegates to the default BearSSL implementation except for X448, whose
 * fixed-width encoding is supplied locally.
 */
static size_t xoff(int curve, size_t *len) {

    size_t ret = 0;

    switch (curve) {
        case BR_EC_curve448:
            *len = 56;
            ret = 0;
            break;
        default:
            ret = ecdhe_orig->xoff(curve, len);
            break;
    }
    return ret;
}

/* fake X448 order, not used */
static const unsigned char _o[56] = {0xff};

/*
 * order - report the encoded subgroup order for a curve
 *
 * @curve: BearSSL curve identifier
 * @len: returns the order length
 *
 * Provides a placeholder order for X448 so the custom EC vtable remains
 * structurally complete. Other curves reuse the default BearSSL metadata.
 */
static const unsigned char *order(int curve, size_t *len) {

    const unsigned char *ret = 0;

    switch (curve) {
        case BR_EC_curve448:
            *len = sizeof _o;
            ret = _o;
            break;
        default:
            ret = ecdhe_orig->order(curve, len);
            break;
    }
    return ret;
}

/*
 * tls_ecdhe_get_default - build the EC implementation used by BearSSL
 *
 * @ctx: TLS context holding the mutable EC implementation copy
 *
 * Clones BearSSL's default EC implementation, restricts it to the curves
 * enabled in ctx, and replaces multiplication hooks with the keyjail pipe
 * helpers used by tlswrapper.
 */
const br_ec_impl *tls_ecdhe_get_default(struct tls_context *ctx) {
    ecdhe_orig = br_ec_get_default();
    memcpy(&ctx->ecdhe_copy, br_ec_get_default(), sizeof(br_ec_impl));
    ctx->ecdhe_copy.supported_curves = ctx->ecdhe_enabled;
    ctx->ecdhe_copy.mulgen = tls_pipe_mulgen;
    ctx->ecdhe_copy.mul = tls_pipe_mul;
    ctx->ecdhe_copy.xoff = xoff;
    ctx->ecdhe_copy.order = order;
    return &ctx->ecdhe_copy;
}
