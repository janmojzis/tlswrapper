#include <string.h>
#include <stdlib.h>
#include "log.h"
#include "tls.h"

typedef struct {
    const char *name;
    uint32_t curve;
} tls_ecdhe;

static const tls_ecdhe tls_ecdhes[] = {
    { "x25519", tls_ecdhe_X25519 },
    { "secp256r1", tls_ecdhe_SECP256R1 },
    { "secp384r1", tls_ecdhe_SECP384R1 },
    { "secp521r1", tls_ecdhe_SECP521R1 },
#ifdef X448
    { "x448", tls_ecdhe_X448 },
#endif
    { 0, 0 }
};

static int use_default = 1;
int tls_ecdhe_add(struct tls_context *ctx, const char *x) {

    size_t i;

    if (use_default == 1) {
        ctx->ecdhe_enabled = 0;
        use_default = 0;
    }

    for (i = 0; tls_ecdhes[i].name; ++i) {
        if (strcmp(x, tls_ecdhes[i].name)) continue;
        ctx->ecdhe_enabled |= (uint32_t) 1 << tls_ecdhes[i].curve;
        return 1;
    }

    log_f2("unable to parse ephemeral algorithm from the string ", x);
    for (i = 0; tls_ecdhes[i].name; ++i) {
        log_f2("available: ", tls_ecdhes[i].name);
    }
    return 0;
}

static const br_ec_impl *ecdhe_orig;

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

/* fake order, not used */
static const unsigned char _o[56] = {0xff};

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

const br_ec_impl *tls_ecdhe_get_default(struct tls_context *ctx) {
    br_ec_impl *ecdhe_copy_p = (br_ec_impl *)&ctx->ecdhe_copy;
    ecdhe_orig = br_ec_get_default();
    memcpy(ecdhe_copy_p, br_ec_get_default(), sizeof(br_ec_impl));
    ecdhe_copy_p->supported_curves = ctx->ecdhe_enabled;
    ecdhe_copy_p->mulgen = tls_pipe_mulgen;
    ecdhe_copy_p->mul = tls_pipe_mul;
    ecdhe_copy_p->xoff = xoff;
    ecdhe_copy_p->order = order;
    return &ctx->ecdhe_copy;
}
