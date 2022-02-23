#include <string.h>
#include <unistd.h>
#include "pipe.h"
#include "randombytes.h"
#include "log.h"
#include "jail.h"
#include "fixpath.h"
#include "tls.h"

extern void br_ssl_engine_switch_chapol_in(br_ssl_engine_context *cc,
                                           int is_client, int prf_id);
extern void br_ssl_engine_switch_chapol_out(br_ssl_engine_context *cc,
                                            int is_client, int prf_id);
extern void br_ssl_engine_switch_gcm_in(br_ssl_engine_context *cc,
                                        int is_client, int prf_id,
                                        const br_block_ctr_class *bc_impl,
                                        size_t cipher_key_len);
extern void br_ssl_engine_switch_gcm_out(br_ssl_engine_context *cc,
                                         int is_client, int prf_id,
                                         const br_block_ctr_class *bc_impl,
                                         size_t cipher_key_len);
extern void br_ssl_engine_compute_master(br_ssl_engine_context *cc, int prf_id,
                                         const void *pms, size_t pms_len);
extern void br_ssl_engine_switch_cbc_in(br_ssl_engine_context *cc,
                                        int is_client, int prf_id, int mac_id,
                                        const br_block_cbcdec_class *bc_impl,
                                        size_t cipher_key_len);
extern void br_ssl_engine_switch_cbc_out(br_ssl_engine_context *cc,
                                         int is_client, int prf_id, int mac_id,
                                         const br_block_cbcenc_class *bc_impl,
                                         size_t cipher_key_len);
extern br_tls_prf_impl br_ssl_engine_get_PRF(br_ssl_engine_context *cc,
                                             int prf_id);

static size_t sign(struct tls_context *ctx, struct tls_pem *pem,
                   unsigned char *key, br_ssl_server_context *cc,
                   unsigned char hash_id, unsigned char *data, size_t hv_len,
                   size_t len) {

    const br_ssl_server_policy_class **vtable = 0;
    size_t ret = 0;
    struct tls_seccrt keycrt = {0};

    /* decrypt pem */
    tls_pem_decrypt(pem, key);

    /* parse secret key */
    if (!tls_seccrt_parse(&keycrt, pem->sec, pem->seclen, ctx->certfn)) {
        log_f3("unable to obtain secret-key from the PEM file '", ctx->certfn,
               "'");
        goto cleanup;
    }
    tls_pem_free(pem);

    /* sign */
    br_ssl_server_zero(cc);
    if (keycrt.key_type == BR_KEYTYPE_EC) {
        br_ssl_server_init_full_ec(cc, 0, 0, 0,
                                   br_skey_decoder_get_ec(&keycrt.keydc));
        vtable = &cc->chain_handler.single_ec.vtable;
    }
    if (keycrt.key_type == BR_KEYTYPE_RSA) {
        br_ssl_server_init_full_rsa(cc, 0, 0,
                                    br_skey_decoder_get_rsa(&keycrt.keydc));
        vtable = &cc->chain_handler.single_rsa.vtable;
    }
    if (vtable) ret = (*vtable)->do_sign(vtable, hash_id, data, hv_len, len);

cleanup:
    randombytes(&keycrt, sizeof keycrt);
    tls_pem_free(pem);
    return ret;
}

static void prf(struct tls_context *ctx, void *dst, size_t len, int prf_id,
                const char *label, unsigned char *seed_data,
                size_t seed_data_len) {

    br_tls_prf_impl iprf;
    br_tls_prf_seed_chunk seed;
    seed.data = seed_data;
    seed.len = seed_data_len;

    iprf = br_ssl_engine_get_PRF(&ctx->cc.eng, prf_id);
    iprf(dst, len, ctx->cc.eng.session.master_secret,
         sizeof ctx->cc.eng.session.master_secret, label, 1, &seed);
}

void tls_keyjail(struct tls_context *ctx) {

    pid_t ppid = getppid();
    unsigned char curve_id;
    unsigned char sk[tls_crypto_scalarmult_MAXSCALARBYTES];
    unsigned char pk[tls_crypto_scalarmult_MAXBYTES];
    size_t pklen;
    unsigned char pemkey[32];
    int prf_id;
    br_ssl_server_context *cc = &ctx->cc;
    struct tls_pem pem = {0};

    log_t1("start keyjail");

    for (;;) {
        size_t fn_len = sizeof ctx->certfn;
        /* read filename from the pipe  */
        if (pipe_readmax(0, ctx->certfn, &fn_len) == -1) goto cleanup;
        if (fn_len == 0) break;
        ctx->certfn[fn_len - 1] = 0;
        /* for security reasons replace '/.' -> '/:' in the filename */
        fixpath(ctx->certfn);
        log_t2("file = ", ctx->certfn);

        /* load the file content to the memory */
        randombytes(pemkey, sizeof pemkey);
        if (!tls_pem_load(&pem, ctx->certfn, pemkey)) {
            if (pipe_writeerrno(1) == -1) goto cleanup;
            continue;
        }

        /* write public-part to the pipe as is (without PEM parsing)  */
        if (pipe_write(1, pem.pub, pem.publen) == -1) { goto cleanup; }
    }

    /* drop privileges, chroot, set limits, ... KEYJAIL starts here */
    if (!ctx->flagnojail) {
        if (jail(ctx->jailaccount, ctx->jaildir, 1) == -1) goto cleanup;
    }

    /* scalar multiplication - keygen */
    if (pipe_readall(0, &curve_id, sizeof(curve_id)) == -1) goto cleanup;
    randombytes(sk, sizeof sk);
    if (tls_crypto_scalarmult_base((unsigned int) curve_id, pk, &pklen, sk) ==
        -1)
        goto cleanup;
    if (pipe_write(1, pk, pklen) == -1) goto cleanup;

    /* signing */
    {
        unsigned char data[2048];
        size_t datalen;
        unsigned char hash_id;
        if (pipe_readall(0, &hash_id, sizeof(hash_id)) == -1) goto cleanup;
        if (pipe_readall(0, &datalen, sizeof(datalen)) == -1) goto cleanup;
        if (datalen > sizeof data) goto cleanup;
        if (pipe_readmax(0, data, &datalen) == -1) goto cleanup;
        datalen =
            sign(ctx, &pem, pemkey, cc, hash_id, data, datalen, sizeof data);
        if (pipe_write(1, data, datalen) == -1) goto cleanup;
    }

    br_ssl_engine_set_chacha20(&cc->eng, &br_chacha20_ct_run);

    /* scalar multiplication */
    if (pipe_readall(0, pk, pklen) == -1) goto cleanup;
    if (pipe_readall(0, &cc->eng.session.session_id,
                     sizeof cc->eng.session.session_id) == -1)
        goto cleanup;
    if (pipe_readall(0, &cc->eng.session.version,
                     sizeof cc->eng.session.version) == -1)
        goto cleanup;
    if (pipe_readall(0, &cc->eng.session.cipher_suite,
                     sizeof cc->eng.session.cipher_suite) == -1)
        goto cleanup;
    if (pipe_readall(0, cc->eng.client_random, sizeof cc->eng.client_random) ==
        -1)
        goto cleanup;
    if (pipe_readall(0, cc->eng.server_random, sizeof cc->eng.server_random) ==
        -1)
        goto cleanup;
    if (tls_crypto_scalarmult((unsigned int) curve_id, pk, &pklen, sk) == -1)
        goto cleanup;

    randombytes(sk, sizeof sk); /* remove secret scalar */

    log_t2("SUITE: ", tls_cipher_str(cc->eng.session.cipher_suite));
    prf_id = br_sha1_ID;
    switch (cc->eng.session.cipher_suite) {
        case BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            prf_id = br_sha256_ID;
            br_ssl_engine_compute_master(&cc->eng, prf_id, pk, pklen);
            br_ssl_engine_switch_chapol_in(&cc->eng, 0, prf_id);
            br_ssl_engine_switch_chapol_out(&cc->eng, 0, prf_id);
            break;
        case BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            prf_id = br_sha384_ID;
            br_ssl_engine_compute_master(&cc->eng, prf_id, pk, pklen);
            br_ssl_engine_switch_gcm_in(&cc->eng, 0, prf_id, cc->eng.iaes_ctr,
                                        32);
            br_ssl_engine_switch_gcm_out(&cc->eng, 0, prf_id, cc->eng.iaes_ctr,
                                         32);
            break;
        case BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            prf_id = br_sha256_ID;
            br_ssl_engine_compute_master(&cc->eng, prf_id, pk, pklen);
            br_ssl_engine_switch_gcm_in(&cc->eng, 0, prf_id, cc->eng.iaes_ctr,
                                        16);
            br_ssl_engine_switch_gcm_out(&cc->eng, 0, prf_id, cc->eng.iaes_ctr,
                                         16);
            break;
        case BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
            prf_id = br_sha384_ID;
            br_ssl_engine_compute_master(&cc->eng, prf_id, pk, pklen);
            br_ssl_engine_switch_cbc_in(&cc->eng, 0, prf_id, prf_id,
                                        cc->eng.iaes_cbcdec, 32);
            br_ssl_engine_switch_cbc_out(&cc->eng, 0, prf_id, prf_id,
                                         cc->eng.iaes_cbcenc, 32);
            break;
        case BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
            prf_id = br_sha256_ID;
            br_ssl_engine_compute_master(&cc->eng, prf_id, pk, pklen);
            br_ssl_engine_switch_cbc_in(&cc->eng, 0, prf_id, prf_id,
                                        cc->eng.iaes_cbcdec, 16);
            br_ssl_engine_switch_cbc_out(&cc->eng, 0, prf_id, prf_id,
                                         cc->eng.iaes_cbcenc, 16);
            break;
        case BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        case BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
            prf_id = br_sha1_ID;
            br_ssl_engine_compute_master(&cc->eng, prf_id, pk, pklen);
            br_ssl_engine_switch_cbc_in(&cc->eng, 0, prf_id, prf_id,
                                        cc->eng.iaes_cbcdec, 32);
            br_ssl_engine_switch_cbc_out(&cc->eng, 0, prf_id, prf_id,
                                         cc->eng.iaes_cbcenc, 32);
            break;
        case BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
            prf_id = br_sha1_ID;
            br_ssl_engine_compute_master(&cc->eng, prf_id, pk, pklen);
            br_ssl_engine_switch_cbc_in(&cc->eng, 0, prf_id, prf_id,
                                        cc->eng.iaes_cbcdec, 16);
            br_ssl_engine_switch_cbc_out(&cc->eng, 0, prf_id, prf_id,
                                         cc->eng.iaes_cbcenc, 16);
            break;
        default:
            break;
    }

    randombytes(pk, sizeof pk); /* remove shared secret */

    while (ppid == getppid()) {

        /* type */
        unsigned char ch;
        if (pipe_readall(0, &ch, sizeof ch) == -1) goto cleanup;
        switch (ch) {
            case tls_pipe_PRF: {
                char label[16];
                unsigned char seed[48];
                size_t seed_len = sizeof seed;
                unsigned char data[12];

                if (pipe_readall(0, label, sizeof label) == -1) goto cleanup;
                if (pipe_readall(0, &seed_len, sizeof seed_len) == -1)
                    goto cleanup;
                if (pipe_readmax(0, seed, &seed_len) == -1) goto cleanup;
                prf(ctx, data, sizeof data, prf_id, label, seed, seed_len);
                if (pipe_write(1, data, sizeof data) == -1) goto cleanup;
            } break;
            case tls_pipe_DECRYPT:
                /* decrypt */
                {
                    int record_type;
                    unsigned int version;
                    unsigned char data[BR_SSL_BUFSIZE_INPUT + 64];
                    size_t data_len;
                    char offset;
                    void *ret;
                    if (pipe_readall(0, &record_type, sizeof record_type) == -1)
                        goto cleanup;
                    if (pipe_readall(0, &version, sizeof version) == -1)
                        goto cleanup;
                    data_len = sizeof data - 64;
                    if (pipe_readmax(0, data + 64, &data_len) == -1)
                        goto cleanup;
                    ret = cc->eng.in.vtable->decrypt(&cc->eng.in.vtable,
                                                     record_type, version,
                                                     data + 64, &data_len);
                    if (!ret) {
                        data_len = 0;
                        offset = 0;
                        if (pipe_write(1, &offset, sizeof offset) == -1)
                            goto cleanup;
                        if (pipe_write(1, 0, 0) == -1) goto cleanup;
                        log_d1("decrypt failed");
                    }
                    else {
                        offset =
                            (char) (long long) ((unsigned long long) ret -
                                                (unsigned long long) data - 64);
                        if (pipe_write(1, &offset, sizeof offset) == -1)
                            goto cleanup;
                        if (pipe_write(1, ret, data_len) == -1) goto cleanup;
                    }
                }
                break;
            case tls_pipe_ENCRYPT:
                /* encrypt */
                {
                    int record_type;
                    unsigned int version;
                    unsigned char data[BR_SSL_BUFSIZE_INPUT + 64];
                    size_t data_len;
                    char offset;
                    void *ret;
                    if (pipe_readall(0, &record_type, sizeof record_type) == -1)
                        goto cleanup;
                    if (pipe_readall(0, &version, sizeof version) == -1)
                        goto cleanup;
                    data_len = sizeof data - 64;
                    if (pipe_readmax(0, data + 64, &data_len) == -1)
                        goto cleanup;
                    ret = cc->eng.out.vtable->encrypt(&cc->eng.out.vtable,
                                                      record_type, version,
                                                      data + 64, &data_len);
                    offset =
                        (char) (long long) ((unsigned long long) ret -
                                            (unsigned long long) data - 64);
                    if (pipe_write(1, &offset, sizeof offset) == -1)
                        goto cleanup;
                    if (pipe_write(1, ret, data_len) == -1) goto cleanup;
                }
                break;
            default:
                goto cleanup;
                break;
        }
    }

cleanup:
    log_t1("finished keyjail");
}
