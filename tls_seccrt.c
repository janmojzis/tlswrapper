/*
 * tls_seccrt.c - parse private keys from PEM input
 *
 * This module decodes the secret-key PEM object used by keyjail signing.
 */

#include "log.h"
#include "randombytes.h"
#include "str.h"
#include "tls.h"

static void parsedummy(void *yv, const void *x, size_t xlen) {
    (void) yv;
    (void) x;
    (void) xlen;
}

static void parsekey(void *ctx, const void *x, size_t xlen) {
    br_skey_decoder_push((br_skey_decoder_context *) ctx, x, xlen);
}

/*
 * tls_seccrt_parse - decode the private key from PEM input
 *
 * @crt: destination structure for the decoded key
 * @buf: PEM input buffer
 * @buflen: size of @buf in bytes
 * @fn: source filename used in log messages
 *
 * Parses the first supported private-key PEM object and initializes the
 * BearSSL secret-key decoder state stored in @crt.
 */
int tls_seccrt_parse(struct tls_seccrt *crt, const char *buf, size_t buflen,
                     const char *fn) {

    br_pem_decoder_context pc;
    long long tlen;
    int inobj = 0;
    int ret = 0;
    int err;
    size_t buflenorig = buflen;

    log_t3("tls_seccrt_parse(buflen = ", log_num(buflen), ")");

    memset(crt, 0, sizeof *crt);
    br_pem_decoder_init(&pc);

    while (buflen > 0) {
        tlen = br_pem_decoder_push(&pc, buf, buflen);
        log_t4("br_pem_decoder_push(len = ", log_num(buflen),
               ") = ", log_num(tlen));
        buf += tlen;
        buflen -= tlen;

        switch (br_pem_decoder_event(&pc)) {
            case BR_PEM_BEGIN_OBJ:
                log_t2("PEM secret-object begin: ", br_pem_decoder_name(&pc));
                if (inobj) {
                    log_e3("malformed PEM secret-object in '", fn, "'");
                    goto cleanup;
                }
                inobj = 1;

                br_pem_decoder_setdest(&pc, parsedummy, &crt->keydc);
                if (str_equal(br_pem_decoder_name(&pc), "EC PRIVATE KEY") ||
                    str_equal(br_pem_decoder_name(&pc), "RSA PRIVATE KEY") ||
                    str_equal(br_pem_decoder_name(&pc), "PRIVATE KEY")) {
                    if (br_skey_decoder_key_type(&crt->keydc)) {
                        log_e3("too many secret-keys in '", fn, "'");
                        goto cleanup;
                    }
                    br_skey_decoder_init(&crt->keydc);
                    br_pem_decoder_setdest(&pc, parsekey, &crt->keydc);
                }
                break;
            case BR_PEM_END_OBJ:
                log_t2("PEM secret-object end: ", br_pem_decoder_name(&pc));
                if (!inobj) {
                    log_e3("malformed PEM secret-object in '", fn, "'");
                    goto cleanup;
                }
                inobj = 0;

                if (str_equal(br_pem_decoder_name(&pc), "EC PRIVATE KEY") ||
                    str_equal(br_pem_decoder_name(&pc), "RSA PRIVATE KEY") ||
                    str_equal(br_pem_decoder_name(&pc), "PRIVATE KEY")) {
                    const br_rsa_private_key *rsakey;
                    const br_ec_private_key *eckey;
                    err = br_skey_decoder_last_error(&crt->keydc);
                    if (err != 0) {
                        log_e5("unable to decode secret-key, err=",
                               tls_error_str(err), " in '", fn, "'");
                        goto cleanup;
                    }
                    crt->key_type = br_skey_decoder_key_type(&crt->keydc);
                    switch (crt->key_type) {
                        case BR_KEYTYPE_RSA:
                            crt->key = br_skey_decoder_get_rsa(&crt->keydc);
                            rsakey = crt->key;
                            log_t2("key=0, sk=RSA, bits=",
                                   log_num(rsakey->n_bitlen));
                            break;
                        case BR_KEYTYPE_EC:
                            crt->key = br_skey_decoder_get_ec(&crt->keydc);
                            eckey = crt->key;
                            log_t2("key=0, sk=EC, id=", log_num(eckey->curve));
                            break;

                        default:
                            log_e5("unknown secret-key type ",
                                   log_num(crt->key_type), " in '", fn, "'");
                            goto cleanup;
                    }
                }
                break;
            case BR_PEM_ERROR:
                log_e3("malformed PEM secret-object in '", fn, "'");
                goto cleanup;
        }
    }

    if (inobj) {
        log_e3("unfinished PEM secret-object in '", fn, "'");
        goto cleanup;
    }

    if (!crt->key) {
        log_e3("no PEM secret-object in '", fn, "'");
        goto cleanup;
    }

    ret = 1;
cleanup:
    randombytes(&pc, sizeof pc);
    log_t4("tls_seccrt_parse(buflen = ", log_num(buflenorig),
           ") = ", log_num(ret));
    return ret;
}
