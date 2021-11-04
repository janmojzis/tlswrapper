#include "log.h"
#include "tls.h"

int tls_anchor_add(struct tls_context *ctx, const char *x) {

    if (ctx->anchorfn) {
        log_f1("unable to add more than one anchor file");
        return 0;
    }
    ctx->anchorfn = x;
    return 1;
}
