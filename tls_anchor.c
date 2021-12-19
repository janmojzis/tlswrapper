#include "tls.h"

int tls_anchor_add(struct tls_context *ctx, char *x) {

    if (ctx->anchorfn) {
        return 0;
    }
    ctx->anchorfn = x;
    return 1;
}
