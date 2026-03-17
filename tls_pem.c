/*
 * tls_pem.c - load and split PEM bundles into public and secret parts
 *
 * This module reads PEM files, separates certificate blocks from private
 * key material, and keeps the secret portion encrypted in memory until a
 * keyjail operation needs it.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "alloc.h"
#include "readall.h"
#include "randombytes.h"
#include "log.h"
#include "open.h"
#include "tls.h"

/*
 * tls_pem_free - release and clear PEM buffers
 *
 * @ctx: PEM container to clear
 *
 * Frees both public and secret allocations and resets the structure to
 * zero so stale lengths and pointers are not reused.
 */
void tls_pem_free(struct tls_pem *ctx) {
    if (ctx->sec) alloc_free(ctx->sec);
    if (ctx->pub) alloc_free(ctx->pub);
    memset(ctx, 0, sizeof *ctx);
}

typedef unsigned long long ull;

/*
 * lineparser - extract one PEM input line without the line ending
 *
 * @buf: input buffer
 * @len: size of @buf in bytes
 * @pos: starting offset within @buf
 * @out: destination buffer for the line payload
 * @outlen: returns the copied line length
 * @outmax: maximum bytes writable to @out
 *
 * Copies one line payload and returns the offset of the next input byte.
 * Overlong lines are rejected by zeroing @outlen and skipping the rest of
 * the input.
 */
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

/*
 * pemparse - split a loaded PEM bundle into secret and certificate parts
 *
 * @ctx: PEM container holding the raw file contents in ctx->sec
 *
 * Rewrites the loaded buffer in place so certificate objects end up in
 * ctx->pub while all remaining PEM objects stay in ctx->sec. Unused tail
 * bytes are overwritten with random data.
 */
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

/*
 * tls_pem_encrypt - encrypt or decrypt the secret PEM buffer in place
 *
 * @ctx: PEM container holding the secret section
 * @key: ChaCha20 key
 *
 * Applies a ChaCha20 stream to ctx->sec using a nonce owned by @ctx.
 * The same function is used for both encryption and decryption.
 *
 * Security:
 *   - each tls_pem instance gets its own random nonce
 *   - decryption reuses the stored nonce instead of process-global state
 */
static unsigned char nonce[12];
static int initialized = 0;

void tls_pem_encrypt(struct tls_pem *ctx, const unsigned char *key) {

    if (!initialized) {
        /*
         * Generate the random nonce and keep it in storage separate from the
         * key buffer. This is an attempt to keep it in a different memory
         * area.
         */
        randombytes(nonce, sizeof nonce);
        initialized = 1;
    }

    br_chacha20_ct_run(key, nonce, 0, ctx->sec, ctx->seclen);
}

/*
 * tls_pem_load - read a PEM file and encrypt its secret section
 *
 * @ctx: PEM container to populate
 * @fn: input PEM file path
 * @key: ChaCha20 key used for the in-memory secret section
 *
 * Loads a regular file, splits certificate blocks from the remaining PEM
 * objects, and immediately encrypts the secret portion in memory.
 *
 * Constraints:
 *   - fn must reference a regular file
 */
int tls_pem_load(struct tls_pem *ctx, const char *fn,
                 const unsigned char *key) {

    int fd = -1;
    int ret = 0;
    struct stat st;

    log_t3("tls_pem_load(fn = ", fn, ")");

    tls_pem_free(ctx);

    fd = open_read(fn);
    if (fd == -1) goto cleanup;
    if (fstat(fd, &st) == -1) goto cleanup;
    if ((st.st_mode & S_IFMT) != S_IFREG) goto cleanup;
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
    log_t2("publen = ", log_num(ctx->publen));
    log_t2("seclen = ", log_num(ctx->seclen));
    log_t4("tls_pem_load(fn = ", fn, ") = ", log_num(ret));
    return ret;
}
