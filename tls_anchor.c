/*
 * tls_anchor.c - configure trust anchor input sources
 *
 * This module stores the pathname used to load trust anchors into a TLS
 * context. It only records the first configured source.
 */

#include "tls.h"

/*
 * tls_anchor_add - register the trust-anchor source file
 *
 * @ctx: TLS context to update
 * @x: path to the trust-anchor PEM file
 *
 * Stores the anchor path when no anchor source has been configured yet.
 * Later calls leave the existing path unchanged.
 */
int tls_anchor_add(struct tls_context *ctx, char *x) {

    if (ctx->anchorfn) return 0;
    ctx->anchorfn = x;
    return 1;
}
