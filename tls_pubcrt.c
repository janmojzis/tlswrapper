/*
20201122
Jan Mojzis
Public domain.
*/

#include <errno.h>
#include "randombytes.h"
#include "alloc.h"
#include "log.h"
#include "stralloc.h"
#include "str.h"
#include "tls.h"

static void parsedummy(void *yv, const void *x, size_t xlen) {
    (void) yv;
    (void) x;
    (void) xlen;
}

static void *xmemdup(const unsigned char *src, size_t len) {

    size_t i;
    unsigned char *buf = alloc(len);
    if (buf) {
        for (i = 0; i < len; ++i) buf[i] = src[i];
    }
    return buf;
}

struct sa {
    unsigned char *s;
    long long len;
    long long alloc;
    int error;
};

static void append(void *xv, const void *buf, size_t buflen) {

    stralloc s;
    struct sa *x = (struct sa *) xv;
    s.s = (char *) x->s;
    s.len = x->len;
    s.alloc = x->alloc;

    if (!stralloc_catb(&s, buf, buflen)) { x->error = errno; }

    x->s = (unsigned char *) s.s;
    x->len = s.len;
    x->alloc = s.alloc;
}

#define XMEMDUP(dst, src, len)                                                 \
    {                                                                          \
        dst = xmemdup(src, len);                                               \
        if (!dst) goto cleanup;                                                \
    }

int tls_pubcrt_parse(struct tls_pubcrt *crt, const char *buf, size_t buflen,
                     const char *fn) {

    long long tlen;
    int inobj = 0;
    int ret = 0;
    struct sa sa = {0};
    br_pem_decoder_context pc;
    br_x509_decoder_context dc5;
    br_x509_pkey *pk;
    int err;
    size_t buflenorig = buflen;

    log_t3("tls_pubcrt_parse(buflen = ", lognum(buflen), ")");

    memset(crt, 0, sizeof *crt);
    br_pem_decoder_init(&pc);

    while (buflen > 0) {
        tlen = br_pem_decoder_push(&pc, buf, buflen);
        if (sa.error) {
            log_e5("br_pem_decoder_push(len = ", lognum(buflen),
                   "), failed in '", fn, "'");
            goto cleanup;
        }
        log_t4("br_pem_decoder_push(len = ", lognum(buflen),
               ") = ", lognum(tlen));
        buf += tlen;
        buflen -= tlen;

        switch (br_pem_decoder_event(&pc)) {
            case BR_PEM_BEGIN_OBJ:
                log_t2("PEM public-object begin: ", br_pem_decoder_name(&pc));
                if (inobj) {
                    log_e3("malformed PEM public-object in '", fn,
                           "', extra BEGIN line");
                    goto cleanup;
                }
                inobj = 1;
                br_pem_decoder_setdest(&pc, parsedummy, 0);
                if (str_equal(br_pem_decoder_name(&pc), "CERTIFICATE") ||
                    str_equal(br_pem_decoder_name(&pc), "X509 CERTIFICATE")) {
                    if (crt->crtlen >= sizeof crt->crt / sizeof crt->crt[0]) {
                        log_e3("too many public PEM certificates in '", fn,
                               "'");
                        goto cleanup;
                    }
                    sa.len = 0;
                    br_pem_decoder_setdest(&pc, append, &sa);
                }
                break;
            case BR_PEM_END_OBJ:
                log_t2("PEM public-object end: ", br_pem_decoder_name(&pc));
                if (!inobj) {
                    log_e3("malformed PEM public-object in '", fn,
                           "', extra END line");
                    goto cleanup;
                }
                inobj = 0;
                if (str_equal(br_pem_decoder_name(&pc), "CERTIFICATE") ||
                    str_equal(br_pem_decoder_name(&pc), "X509 CERTIFICATE")) {
                    XMEMDUP(crt->crt[crt->crtlen].data, sa.s, sa.len);
                    crt->crt[crt->crtlen].data_len = sa.len;

                    sa.len = 0;
                    br_x509_decoder_init(&dc5, append, &sa);
                    br_x509_decoder_push(&dc5, crt->crt[crt->crtlen].data,
                                         crt->crt[crt->crtlen].data_len);
                    if (sa.error) {
                        log_e3("br_x509_decoder_push(len = ",
                               lognum(crt->crt[crt->crtlen].data_len),
                               "), failed");
                        goto cleanup;
                    }

                    err = br_x509_decoder_last_error(&dc5);
                    if (err != 0) {
                        log_e2("unable to decode public-key, err=",
                               tls_error_str(err));
                        goto cleanup;
                    }

                    pk = br_x509_decoder_get_pkey(&dc5);
                    if (!pk) {
                        log_e1("br_x509_decoder_get_pkey no public-key in PEM "
                               "public-object");
                        goto cleanup;
                    }
                    XMEMDUP(crt->ta[crt->talen].dn.data, sa.s, sa.len);
                    crt->ta[crt->talen].dn.len = sa.len;
                    crt->ta[crt->talen].flags = 0;
                    if (br_x509_decoder_isCA(&dc5)) {
                        crt->ta[crt->talen].flags |= BR_X509_TA_CA;
                    }

                    switch (pk->key_type) {
                        case BR_KEYTYPE_EC:
                            crt->ta[crt->talen].pkey.key_type = BR_KEYTYPE_EC;
                            crt->ta[crt->talen].pkey.key.ec.curve =
                                pk->key.ec.curve;
                            XMEMDUP(crt->ta[crt->talen].pkey.key.ec.q,
                                    pk->key.ec.q, pk->key.ec.qlen);
                            crt->ta[crt->talen].pkey.key.ec.qlen =
                                pk->key.ec.qlen;
                            if (crt->crtlen == 0) crt->key_type = BR_KEYTYPE_EC;
                            break;
                        case BR_KEYTYPE_RSA:
                            crt->ta[crt->talen].pkey.key_type = BR_KEYTYPE_RSA;
                            XMEMDUP(crt->ta[crt->talen].pkey.key.rsa.n,
                                    pk->key.rsa.n, pk->key.rsa.nlen);
                            crt->ta[crt->talen].pkey.key.rsa.nlen =
                                pk->key.rsa.nlen;
                            XMEMDUP(crt->ta[crt->talen].pkey.key.rsa.e,
                                    pk->key.rsa.e, pk->key.rsa.elen);
                            crt->ta[crt->talen].pkey.key.rsa.elen =
                                pk->key.rsa.elen;
                            if (crt->crtlen == 0)
                                crt->key_type = BR_KEYTYPE_RSA;
                            break;
                        default:
                            log_e5("br_x509_decoder_get_pkey unsupported "
                                   "public-key type id=",
                                   lognum(pk->key_type), " in '", fn, "'");
                            goto cleanup;
                    }
                    {
                        const char *sigtype = tls_keytype_str(
                            br_x509_decoder_get_signer_key_type(&dc5));
                        const char *pktype = tls_keytype_str(pk->key_type);
                        const char *strca = "0";
                        if (br_x509_decoder_isCA(&dc5)) strca = "1";
                        log_t8("crt=", lognum(crt->crtlen), ", pk=", pktype,
                               ", sig=", sigtype, ", ca=", strca);
                    }
                    crt->crtlen += 1;
                    crt->talen += 1;
                }
                break;
            case BR_PEM_ERROR:
                log_e3("malformed PEM public-object in '", fn, "'");
                goto cleanup;
        }
    }

    if (inobj) {
        log_e3("unfinished PEM public-object in '", fn, "'");
        goto cleanup;
    }

    if (crt->crtlen == 0) {
        log_e3("no PEM public-object in '", fn, "'");
        goto cleanup;
    }

    ret = 1;
cleanup:
    randombytes(&pc, sizeof pc);
    randombytes(&dc5, sizeof dc5);
    log_t4("tls_pubcrt_parse(buflen = ", lognum(buflenorig),
           ") = ", lognum(ret));
    return ret;
}
