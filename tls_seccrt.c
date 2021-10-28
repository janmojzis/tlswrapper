#include "log.h"
#include "tls.h"

static void parsedummy(void *yv, const void *x, size_t xlen) {
    (void) yv;
    (void) x;
    (void) xlen;
}

static void parsekey(void *ctx, const void *x, size_t xlen) {
    br_skey_decoder_push((br_skey_decoder_context *)ctx, x, xlen);
}

int tls_seccrt_parse(struct tls_seccrt *crt, const char *buf, size_t buflen) {

    br_pem_decoder_context pc;
    long long tlen;
    int inobj = 0;
    int ret = 0;
    int err;

    memset(crt, 0, sizeof *crt);
    br_pem_decoder_init(&pc);

    while (buflen > 0) {
        tlen = br_pem_decoder_push(&pc, buf, buflen);
        log_t4("br_pem_decoder_push(len = ", lognum(buflen), ") = ", lognum(tlen));
        buf += tlen;
        buflen -= tlen;

        switch (br_pem_decoder_event(&pc)) {
            case BR_PEM_BEGIN_OBJ:
                log_t2("object begin: ", br_pem_decoder_name(&pc));
                if (inobj) {
                    log_w1("malformed PEM object");
                    goto cleanup;
                }
                inobj = 1;

                br_pem_decoder_setdest(&pc, parsedummy, &crt->keydc);
                if (!strcmp(br_pem_decoder_name(&pc), "EC PRIVATE KEY") ||
                    !strcmp(br_pem_decoder_name(&pc), "RSA PRIVATE KEY") ||
                    !strcmp(br_pem_decoder_name(&pc), "PRIVATE KEY")) {
                    if (br_skey_decoder_key_type(&crt->keydc)) {
                        log_w1("too many keys in PEM file");
                        goto cleanup;
                    }
                    br_skey_decoder_init(&crt->keydc);
                    br_pem_decoder_setdest(&pc, parsekey, &crt->keydc);
                }
                break;
            case BR_PEM_END_OBJ:
                log_t2("object end: ", br_pem_decoder_name(&pc));
                if (!inobj) {
                    log_w1("malformed PEM object");
                    goto cleanup;
                }
                inobj = 0;

                if (!strcmp(br_pem_decoder_name(&pc), "EC PRIVATE KEY") ||
                    !strcmp(br_pem_decoder_name(&pc), "RSA PRIVATE KEY") ||
                    !strcmp(br_pem_decoder_name(&pc), "PRIVATE KEY")) {
                    const br_rsa_private_key *rsakey;
                    const br_ec_private_key *eckey;
                    err = br_skey_decoder_last_error(&crt->keydc);
                    if (err != 0) {
                        log_w2("unable to decode private key, err=", lognum(err));
                        goto cleanup;
                    }
                    crt->key_type = br_skey_decoder_key_type(&crt->keydc);
                    switch (crt->key_type) {
                        case BR_KEYTYPE_RSA:
                            crt->key = br_skey_decoder_get_rsa(&crt->keydc);
                            rsakey = crt->key;
                            log_t2("key=0, sk=RSA, bits=", lognum(rsakey->n_bitlen));
                            break;
                        case BR_KEYTYPE_EC:
                            crt->key = br_skey_decoder_get_ec(&crt->keydc);
                            eckey = crt->key;
                            log_t2("key=0, sk=EC, id=", lognum(eckey->curve));
                            break;

                        default:
                            log_w1("unknown private key type");
                    }
                }
                break;
            case BR_PEM_ERROR:
                log_w1("malformed PEM object");
                goto cleanup;
        }
    }

    if (inobj) {
        log_w1("unfinished PEM object");
        goto cleanup;
    }

    ret = 1;
cleanup:
    return ret;
}
