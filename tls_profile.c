#include "log.h"
#include "randombytes.h"
#include "tls.h"

static int hash_choose(unsigned int bf) {
    const unsigned char pref[] = {
        br_sha512_ID, br_sha384_ID, br_sha256_ID
        , br_sha1_ID
    };
    size_t u;

    for (u = 0; u < sizeof pref; u ++) {
        int x;
        x = pref[u];
        if ((bf >> x) & 1) {
            return x;
        }
    }
    return 0;
}

int tls_choose(const br_ssl_server_policy_class **pctx, const br_ssl_server_context *cc, br_ssl_server_choices *choices) {
    const br_suite_translated *st;
    size_t i, u, st_num;
    unsigned int chashes;
    struct tls_context *ctx = (struct tls_context *)pctx;
    const char *server_name;

    log_t1("tls_choose()");

    st = br_ssl_server_get_client_suites(cc, &st_num);
    chashes = br_ssl_server_get_client_hashes(cc);
    server_name = br_ssl_engine_get_server_name(&cc->eng);

    for (u = 0; u < st_num; ++u) {
        log_d2("clients cipher ", tls_cipher_str(st[u][0]));
    }

    log_d2("client tls_version=", tls_version_str(br_ssl_engine_get_version(&cc->eng)));
    log_d3("client server_name='", br_ssl_engine_get_server_name(&cc->eng),"'");


    for (i = 0; i < ctx->certfiles_len; ++i) {
        if (ctx->certfiles[i].filetype == S_IFDIR && strlen(server_name) == 0) {
            continue;
        }
        if (ctx->certfiles[i].filetype == S_IFDIR) {
            /* certificate directory, but server didn't send SNI server_name */
            if (strlen(server_name) == 0) continue;
            if (!tls_pipe_getcert(ctx->chain, &ctx->chain_len, &ctx->key_type, ctx->certfiles[i].name, server_name)) {
                log_w4("unable to get certificate from PEM file ", ctx->certfiles[i].name, "/", server_name);
                continue;
            }
        }
        if (ctx->certfiles[i].filetype == S_IFREG) {
            /* certificate file -> ignore SNI server_name */
            if (!tls_pipe_getcert(ctx->chain, &ctx->chain_len, &ctx->key_type, 0, ctx->certfiles[i].name)) {
                log_w2("unable to get certificate from PEM file ", ctx->certfiles[i].name);
                continue;
            }
        }

        for (u = 0; u < st_num; ++u) {
            unsigned int tt;

            tt = st[u][1];
            if ((tt >> 12) == BR_SSLKEYX_ECDHE_ECDSA && ctx->key_type == BR_KEYTYPE_EC) {
                log_t1("BR_SSLKEYX_ECDHE_ECDSA");

                choices->chain = ctx->chain;
                choices->chain_len = ctx->chain_len;
                choices->cipher_suite = st[u][0];
                if (br_ssl_engine_get_version(&cc->eng) < BR_TLS12) {
                    choices->algo_id = 0xFF00 + br_sha1_ID;
                } 
                else {
                    choices->algo_id = 0xFF00 + hash_choose(chashes >> 8);
                }
                goto ok;
            }
            if ((tt >> 12) == BR_SSLKEYX_ECDHE_RSA && ctx->key_type == BR_KEYTYPE_RSA) {
                log_t1("BR_SSLKEYX_ECDHE_RSA");
                choices->chain = ctx->chain;
                choices->chain_len = ctx->chain_len;
                choices->cipher_suite = st[u][0];
                if (br_ssl_engine_get_version(&cc->eng) < BR_TLS12) {
                    choices->algo_id = 0xFF00;
                } 
                else {
                    choices->algo_id = 0xFF00 + hash_choose(chashes);
                }
                goto ok;
            }
        }
    }
    if (i == ctx->certfiles_len) log_e1("no usable PEM certificate");
    log_t1("tls_choose() = 0");
    return 0;
ok:
    log_t1("tls_choose() = 1");
    return 1;
}

static const br_ssl_server_policy_class tls_policy_vtable = {
    sizeof(struct tls_context),
    tls_choose,
    0, /* keyx */ 
    tls_pipe_dosign
};

void tls_profile(struct tls_context *ctx) {

    const char *name;
    unsigned char seed[32];
    br_ssl_server_context *cc = &ctx->cc;

    log_t1("tls_profile() begin");
    
    /*
     * Reset server context and set supported versions.
     */
    br_ssl_server_zero(cc);
    br_ssl_engine_set_versions(&cc->eng, ctx->version_min, ctx->version_max);

    /*
     * Set flags
     */
    br_ssl_engine_set_all_flags(&cc->eng, ctx->flags);
    
    /*
     * Set cipher suites implementation
     */
    br_ssl_engine_set_suites(&cc->eng, ctx->cipher_enabled, ctx->cipher_enabled_len);

    /*
     * Set ECDHE ciphers
     */
    br_ssl_engine_set_ec(&cc->eng, tls_ecdhe_get_default(ctx));
    
    /*
     * Set the "server policy"
     */
    ctx->vtable = &tls_policy_vtable;
    br_ssl_server_set_policy(cc, &ctx->vtable);
    
    /*
     * Set supported hash functions.
     */
    br_ssl_engine_set_hash(&cc->eng, br_md5_ID, &br_md5_vtable);
    br_ssl_engine_set_hash(&cc->eng, br_sha1_ID, &br_sha1_vtable);
    br_ssl_engine_set_hash(&cc->eng, br_sha256_ID, &br_sha256_vtable);
    br_ssl_engine_set_hash(&cc->eng, br_sha384_ID, &br_sha384_vtable);
    br_ssl_engine_set_hash(&cc->eng, br_sha512_ID, &br_sha512_vtable);

    /*
     * Set the PRF implementations.
     */
    br_ssl_engine_set_prf10(&cc->eng, &tls_pipe_prf);
    br_ssl_engine_set_prf_sha256(&cc->eng, &tls_pipe_prf);
    br_ssl_engine_set_prf_sha384(&cc->eng, &tls_pipe_prf);
    
    /*
     * Symmetric encryption.
     */
    br_ssl_engine_set_chapol(&cc->eng, &tls_pipe_chapol_in_vtable, &tls_pipe_chapol_out_vtable);
    br_ssl_engine_set_gcm(&cc->eng, &tls_pipe_gcm_in_vtable, &tls_pipe_gcm_out_vtable);
    br_ssl_engine_set_default_aes_cbc(&cc->eng);
    br_ssl_engine_set_cbc(&cc->eng, &tls_pipe_cbc_in_vtable, &tls_pipe_cbc_out_vtable);

    /*
     * If trust anchors have been configured, then set an X.509
     * validation engine and activate client certificate
     * authentication.
     */
    if (ctx->anchorcrt.talen > 0) {
        br_x509_minimal_init(&ctx->xc, &br_sha256_vtable, ctx->anchorcrt.ta, ctx->anchorcrt.talen);
        br_x509_minimal_set_hash(&ctx->xc, br_sha256_ID, &br_sha256_vtable);
        br_x509_minimal_set_hash(&ctx->xc, br_sha384_ID, &br_sha384_vtable);
        br_x509_minimal_set_hash(&ctx->xc, br_sha512_ID, &br_sha512_vtable);
        br_ssl_engine_set_default_rsavrfy(&cc->eng);
        br_ssl_engine_set_ecdsa(&cc->eng, &tls_ecdsa_vrfy_asn1);
        br_x509_minimal_set_rsa(&ctx->xc, br_rsa_pkcs1_vrfy_get_default());
        br_x509_minimal_set_ecdsa(&ctx->xc, br_ec_get_default(), br_ecdsa_vrfy_asn1_get_default());
        br_ssl_engine_set_x509(&cc->eng, &ctx->xc.vtable);
        br_ssl_server_set_trust_anchor_names_alt(cc, ctx->anchorcrt.ta, ctx->anchorcrt.talen);
    }

    /*
     * IO buffer
     */
    br_ssl_engine_set_buffer(&cc->eng, ctx->iobuf, sizeof ctx->iobuf, 1);

    /*
     * Inject entropy from randombytes()
     */
    randombytes(seed, sizeof seed);
    br_ssl_engine_inject_entropy(&cc->eng, seed, sizeof seed);
    randombytes(seed, sizeof seed);
    br_prng_seeder_system(&name);
    log_t2("system seeder: ", name);

    /*
     * Reset
     */
    br_ssl_server_reset(cc);

    log_t1("tls_profile() end");
}
