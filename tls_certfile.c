/*
 * tls_certfile.c - register certificate file and directory sources
 *
 * This module records the PEM locations that tlswrapper may search when
 * selecting a server certificate. Entries retain their original type so
 * SNI-based directory lookups and direct file lookups stay distinct.
 */

#include "tls.h"

/*
 * tls_certfile_add_dir - append a certificate directory source
 *
 * @ctx: TLS context to update
 * @fn: directory path containing per-name PEM files
 *
 * Adds a directory entry to the certificate search list. Returns 0 when
 * the fixed-size list is already full.
 */
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

/*
 * tls_certfile_add_file - append a certificate file source
 *
 * @ctx: TLS context to update
 * @fn: PEM file path
 *
 * Adds a regular-file entry to the certificate search list. Returns 0
 * when the fixed-size list is already full.
 */
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
