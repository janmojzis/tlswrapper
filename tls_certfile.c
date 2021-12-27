/*
20211103
Jan Mojzis
Public domain.
*/

#include "tls.h"

int tls_certfile_add_dir(struct tls_context *ctx, const char *fn) {

    if ((sizeof ctx->certfiles / sizeof ctx->certfiles[0]) <=
        ctx->certfiles_len) {
        return 0;
    }

    ctx->certfiles[ctx->certfiles_len].name = fn;
    ctx->certfiles[ctx->certfiles_len].filetype = S_IFDIR;
    ++ctx->certfiles_len;
    return 1;
}

int tls_certfile_add_file(struct tls_context *ctx, const char *fn) {

    if ((sizeof ctx->certfiles / sizeof ctx->certfiles[0]) <=
        ctx->certfiles_len) {
        return 0;
    }

    ctx->certfiles[ctx->certfiles_len].name = fn;
    ctx->certfiles[ctx->certfiles_len].filetype = S_IFREG;
    ++ctx->certfiles_len;
    return 1;
}
