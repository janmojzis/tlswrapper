/*
20211103
Jan Mojzis
Public domain.
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tls.h"
#include "log.h"

int tls_certfile_add_dir(struct tls_context *ctx, const char *fn) {

    struct stat st;
    int ret = 0;

    if (stat(fn, &st) == -1) {
        log_f2("unable to stat certdir ", fn);
        goto cleanup;
    }
    if ((st.st_mode & S_IFMT) != S_IFDIR) {
        log_f3("unable to add certdir ", fn, ": not a directory");
        goto cleanup;
    }

    if ((sizeof ctx->certfiles / sizeof ctx->certfiles[0]) <= ctx->certfiles_len) {
        log_f3("unable to add certdir ", fn, ": too many certs");
        goto cleanup;
    }

    ctx->certfiles[ctx->certfiles_len].name = fn;
    ctx->certfiles[ctx->certfiles_len].filetype = S_IFDIR;
    ++ctx->certfiles_len;
    ret = 1;

cleanup:
    return ret;
}

int tls_certfile_add_file(struct tls_context *ctx, const char *fn) {

    struct stat st;
    int ret = 0;

    if (stat(fn, &st) == -1) {
        log_f2("unable to stat certfile ", fn);
        goto cleanup;
    }
    if ((st.st_mode & S_IFMT) != S_IFREG) {
        log_f3("unable to add certfile ", fn, ": not a file");
        goto cleanup;
    }

    if ((sizeof ctx->certfiles / sizeof ctx->certfiles[0]) <= ctx->certfiles_len) {
        log_f3("unable to add certfile ", fn, ": too many certs");
        goto cleanup;
    }

    ctx->certfiles[ctx->certfiles_len].name = fn;
    ctx->certfiles[ctx->certfiles_len].filetype = S_IFREG;
    ++ctx->certfiles_len;
    ret = 1;

cleanup:
    return ret;
}
