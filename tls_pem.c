/*
20201122
Jan Mojzis
Public domain.
*/

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "alloc.h"
#include "readall.h"
#include "randombytes.h"
#include "log.h"
#include "tls.h"

void tls_pem_free(struct tls_pem *ctx) {
    if (ctx->sec) alloc_free(ctx->sec);
    if (ctx->pub) alloc_free(ctx->pub);
    memset(ctx, 0, sizeof *ctx);
}

typedef unsigned long long ull;

static ull lineparser(const char *buf, ull len, ull pos, char *out, ull *outlen,
                      ull outmax) {

    ull i;

    *outlen = 0;
    for (i = pos; i < len; ++i) {
        if (buf[i] == '\r') return i + 1;
        if (buf[i] == '\n') return i + 1;
        if (*outlen >= outmax) {
            /* skip the rest */
            *outlen = 0;
            return len;
        }
        out[(*outlen)++] = buf[i];
    }
    return len;
}

static void pemparse(struct tls_pem *ctx) {

    unsigned long long pos = 0;
    int flagpub = 0;
    char line[65];
    unsigned long long linelen;
    unsigned long long seclen = 0;
    unsigned long long publen = 0;

    while (ctx->seclen > pos) {
        pos = lineparser(ctx->sec, ctx->seclen, pos, line, &linelen,
                         sizeof line - 1);
        if (linelen == 0) continue;
        line[linelen++] = '\n';
        if (linelen == 28 &&
            !memcmp(line, "-----BEGIN CERTIFICATE-----", linelen - 1))
            flagpub = 1;
        if (linelen == 33 &&
            !memcmp(line, "-----BEGIN X509 CERTIFICATE-----", linelen - 1))
            flagpub = 1;
        if (flagpub) {
            memcpy(ctx->pub + publen, line, linelen);
            publen += linelen;
        }
        else {
            memcpy(ctx->sec + seclen, line, linelen);
            seclen += linelen;
        }
        if (linelen == 26 &&
            !memcmp(line, "-----END CERTIFICATE-----", linelen - 1))
            flagpub = 0;
        if (linelen == 31 &&
            !memcmp(line, "-----END X509 CERTIFICATE-----", linelen - 1))
            flagpub = 0;
    }
    randombytes(line, sizeof line);
    randombytes(ctx->sec + seclen, ctx->alloc - seclen);
    randombytes(ctx->pub + publen, ctx->alloc - publen);
    ctx->seclen = seclen;
    ctx->publen = publen;
}

static unsigned char nonce[12];
static int initialized = 0;

void tls_pem_encrypt(struct tls_pem *ctx, const unsigned char *key) {

    if (!initialized) {
        randombytes(nonce, sizeof nonce);
        initialized = 1;
    }

    br_chacha20_ct_run(key, nonce, 0, ctx->sec, ctx->seclen);
}

/*
The 'tls_pem_load' loads secret PEM part and public PEM part
from the file fn to the memory and immediately encrypts secret part.
*/

int tls_pem_load(struct tls_pem *ctx, const char *fn,
                 const unsigned char *key) {

    int fd = -1;
    int ret = 0;
    struct stat st;

    log_t3("tls_pem_load(fn = ", fn, ")");

    tls_pem_free(ctx);

    fd = open(fn, O_RDONLY | O_NONBLOCK);
    if (fd == -1) goto cleanup;
    if (fstat(fd, &st) == -1) goto cleanup;
    ctx->alloc = ctx->seclen = st.st_size;
    ctx->alloc += 1;
    ctx->sec = alloc(ctx->alloc);
    if (!ctx->sec) goto cleanup;
    ctx->pub = alloc(ctx->alloc);
    if (!ctx->pub) goto cleanup;
    if (readall(fd, ctx->sec, ctx->seclen) == -1) goto cleanup;
    ctx->sec[ctx->seclen++] = '\n';
    pemparse(ctx);
    tls_pem_encrypt(ctx, key);
    ret = 1;
cleanup:
    if (fd != -1) close(fd);
    if (ret == 0) tls_pem_free(ctx);
    log_t2("publen = ", lognum(ctx->publen));
    log_t2("seclen = ", lognum(ctx->seclen));
    log_t4("tls_pem_load(fn = ", fn, ") = ", lognum(ret));
    return ret;
}
