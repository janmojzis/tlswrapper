#include "tls.h"
#include "pipe.h"
#include "randombytes.h"
#include "alloc.h"
#include "log.h"

int tls_pipe_fromchild = -1;
int tls_pipe_tochild = -1;
br_ssl_engine_context *tls_pipe_eng;

int tls_pipe_getcert(br_x509_certificate *chain, size_t *chain_len, char *key_type, const char *dir, const char *name) {

    int ret = 0;
    size_t i;
    char *pubpem = 0;
    size_t pubpemlen;
    struct tls_pubcrt crt = {0};

    /* write filename */
    if (pipe_writefn(tls_pipe_tochild, dir, name) == -1) goto cleanup;

    /* read PEM */
    pubpem = pipe_readalloc(tls_pipe_fromchild, &pubpemlen);
    if (!pubpem) goto cleanup;

    /* parse PEM */
    if (!tls_pubcrt_parse(&crt, pubpem, pubpemlen)) goto cleanup;

    /* key type*/
    *key_type = crt.key_type;

    /* chain */
    for (i = 0; i < crt.crtlen; ++i) {
        chain[i].data_len = crt.crt[i].data_len;
        chain[i].data = crt.crt[i].data;
    }
    *chain_len = crt.crtlen;

    ret = 1;
cleanup:
    if (pubpem) alloc_free(pubpem);
    return ret;
}

size_t tls_pipe_mulgen(unsigned char *R, const unsigned char *x, size_t xlen, int curve) {

    unsigned char curve_id = (unsigned int) curve;
    size_t Glen;
    (void) x;
    (void) xlen;

    log_t1("tls_pipe_mulgen begin");

    /* finish certs */
    if (pipe_write(tls_pipe_tochild, 0, 0) == -1) goto fail;

    /* write curve */
    if (pipe_write(tls_pipe_tochild, &curve_id, sizeof curve_id) == -1) goto fail;

    /* read point */
    Glen = 133;
    if (pipe_readmax(tls_pipe_fromchild, R, &Glen) == -1) goto fail;
    return Glen;

fail:
    log_e1("tls_pipe_mulgen failed");
    return 0;
}

size_t tls_pipe_dosign(const br_ssl_server_policy_class **pctx, unsigned int algo_id, unsigned char *data, size_t len, size_t max) {

    unsigned char hash_id = algo_id & 0xff;
    (void) pctx;

    log_t4("tls_pipe_dosign begin: algo_id=", lognum(algo_id), ", len=", lognum(len));

    /* write hash_id */
    if (pipe_write(tls_pipe_tochild, &hash_id, sizeof hash_id) == -1) goto fail;

    /* write max */
    if (pipe_write(tls_pipe_tochild, &max, sizeof max) == -1) goto fail;

    /* write data */
    if (pipe_write(tls_pipe_tochild, data, len) == -1) goto fail;

    /* read the signature */
    if (pipe_readmax(tls_pipe_fromchild, data, &max) == -1) goto fail;

    log_t1("tls_pipe_dosign success");
    return max;

fail:
    log_e1("tls_pipe_dosign failed");
    return 0;
}

uint32_t tls_pipe_mul(unsigned char *G, size_t Glen, const unsigned char *x, size_t xlen, int curve) {

    (void) curve;
    (void) x;
    (void) xlen;


    /* write pk */
    if (pipe_write(tls_pipe_tochild, G, Glen) == -1) goto fail;

    /* write tls version, client_random, server_random */
    /* XXX is better place ?? */
    if (pipe_write(tls_pipe_tochild, &tls_pipe_eng->session.version, sizeof tls_pipe_eng->session.version) == -1) goto fail;
    if (pipe_write(tls_pipe_tochild, &tls_pipe_eng->session.cipher_suite, sizeof tls_pipe_eng->session.cipher_suite) == -1) goto fail;
    if (pipe_write(tls_pipe_tochild, tls_pipe_eng->client_random, sizeof tls_pipe_eng->client_random) == -1) goto fail;
    if (pipe_write(tls_pipe_tochild, tls_pipe_eng->server_random, sizeof tls_pipe_eng->server_random) == -1) goto fail;

    log_t1("tls_pipe_mul success");
    return 1;

fail:
    log_e1("tls_pipe_mul failed");
    return 0;
}

void tls_pipe_prf(void *dst, size_t len, const void *secret, size_t secret_len, const char *label, size_t seed_num, const br_tls_prf_seed_chunk *seed) {

    unsigned char ch = tls_pipe_PRF;
    (void) secret;
    (void) secret_len;

    if (strcmp(label, "client finished") && strcmp(label, "server finished")) goto randomoutput;
    if (seed_num != 1) goto randomoutput;

    if (pipe_write(tls_pipe_tochild, &ch, sizeof ch) == -1) goto randomoutput;
    if (pipe_write(tls_pipe_tochild, label, strlen(label) + 1) == -1) goto randomoutput;
    if (pipe_write(tls_pipe_tochild, &seed->len, sizeof seed->len) == -1) goto randomoutput;
    if (pipe_write(tls_pipe_tochild, seed->data, seed->len) == -1) goto randomoutput;
    if (pipe_readall(tls_pipe_fromchild, dst, len) == -1) goto randomoutput;
    log_t3("tls_pipe_prf(", label, ") finished");
    return;

randomoutput:
    log_t3("tls_pipe_prf(", label, ") finished with random output");
    randombytes(dst, len);
}


static int chapol_check_length(const br_sslrec_in_class *const *cc, size_t rlen) {
    return br_sslrec_in_chapol_vtable.inner.check_length(cc, rlen);
}
static int gcm_check_length(const br_sslrec_in_class *const *cc, size_t rlen) {
    return br_sslrec_in_gcm_vtable.inner.check_length(cc, rlen);
}
static int cbc_check_length(const br_sslrec_in_class *const *cc, size_t rlen) {
    return br_sslrec_in_cbc_vtable.inner.check_length(cc, rlen);
}

static void in_chapol_init(const br_sslrec_in_chapol_class **cc, br_chacha20_run ichacha, br_poly1305_run ipoly, const void *key, const void *iv) {
    br_sslrec_chapol_context *ctx = (br_sslrec_chapol_context *)cc;
    (void) ichacha; (void) ipoly; (void) key; (void) iv;
    ctx->vtable.in = &tls_pipe_chapol_in_vtable;
}
static void in_gcm_init(br_sslrec_gcm_context *cc, const br_block_ctr_class *bc_impl, const void *key, size_t key_len, br_ghash gh_impl, const void *iv) {
    (void) bc_impl; (void) key; (void) key_len; (void) gh_impl; (void) iv;
    cc->vtable.in = &tls_pipe_gcm_in_vtable;
}

static void
in_cbc_init(br_sslrec_in_cbc_context *cc,
    const br_block_cbcdec_class *bc_impl,
    const void *bc_key, size_t bc_key_len,
    const br_hash_class *dig_impl,
    const void *mac_key, size_t mac_key_len, size_t mac_out_len,
    const void *iv)
{
    cc->vtable = &tls_pipe_cbc_in_vtable;
    cc->seq = 0;
    bc_impl->init(&cc->bc.vtable, bc_key, bc_key_len);
    br_hmac_key_init(&cc->mac, dig_impl, mac_key, mac_key_len);
    cc->mac_len = mac_out_len;
    if (iv == NULL) {
        memset(cc->iv, 0, sizeof cc->iv);
        cc->explicit_IV = 1;
    } else {
        memcpy(cc->iv, iv, bc_impl->block_size);
        cc->explicit_IV = 0;
    }
}

static unsigned char *decrypt(const br_sslrec_in_class **cc, int record_type, unsigned version, void *datav, size_t *data_len) {
    unsigned char ch = tls_pipe_DECRYPT;
    unsigned char *data = datav;
    char offset = 0;
    (void) cc;
    log_t1("decrypt begin");
    if (pipe_write(tls_pipe_tochild, &ch, sizeof ch) == -1) goto fail;
    if (pipe_write(tls_pipe_tochild, &record_type, sizeof record_type) == -1) goto fail;
    if (pipe_write(tls_pipe_tochild, &version, sizeof version) == -1) goto fail;
    if (pipe_write(tls_pipe_tochild, data, *data_len) == -1) goto fail;
    if (pipe_readall(tls_pipe_fromchild, &offset, sizeof offset) == -1) goto fail;
    if (pipe_readmax(tls_pipe_fromchild, data + offset, data_len) == -1) goto fail;
    if (!*data_len) goto fail;
    log_t1("decrypt finished");
    return data + offset;
fail:
    log_e1("decrypt failed");
    return 0;
}

const br_sslrec_in_chapol_class tls_pipe_chapol_in_vtable = {
    {
        sizeof(br_sslrec_chapol_context),
        (int (*)(const br_sslrec_in_class *const *, size_t)) &chapol_check_length,
        (unsigned char *(*)(const br_sslrec_in_class **, int, unsigned, void *, size_t *)) &decrypt
    },
    (void (*)(const br_sslrec_in_chapol_class **, br_chacha20_run, br_poly1305_run, const void *, const void *)) &in_chapol_init
};


const br_sslrec_in_gcm_class tls_pipe_gcm_in_vtable = {
    {
        sizeof(br_sslrec_gcm_context),
        (int (*)(const br_sslrec_in_class *const *, size_t))
            &gcm_check_length,
        (unsigned char *(*)(const br_sslrec_in_class **,
            int, unsigned, void *, size_t *))
            &decrypt
    },
    (void (*)(const br_sslrec_in_gcm_class **,
        const br_block_ctr_class *, const void *, size_t,
        br_ghash, const void *))
        &in_gcm_init
};

const br_sslrec_in_cbc_class tls_pipe_cbc_in_vtable = {
    {
        sizeof(br_sslrec_in_cbc_context),
        (int (*)(const br_sslrec_in_class *const *, size_t))
            &cbc_check_length,
        (unsigned char *(*)(const br_sslrec_in_class **,
            int, unsigned, void *, size_t *))
            &decrypt
    },
    (void (*)(const br_sslrec_in_cbc_class **,
        const br_block_cbcdec_class *, const void *, size_t,
        const br_hash_class *, const void *, size_t, size_t,
        const void *))
        &in_cbc_init
};

static void chapol_max_plaintext(const br_sslrec_out_class *const *cc, size_t *start, size_t *end) {
    br_sslrec_out_chapol_vtable.inner.max_plaintext(cc, start, end);
}

static void gcm_max_plaintext(const br_sslrec_out_class *const *cc, size_t *start, size_t *end) {
    br_sslrec_out_gcm_vtable.inner.max_plaintext(cc, start, end);
}

static void cbc_max_plaintext(const br_sslrec_out_class *const *cc, size_t *start, size_t *end) {
    br_sslrec_out_cbc_vtable.inner.max_plaintext(cc, start, end);
}

static unsigned char *encrypt(const br_sslrec_out_class **cc, int record_type, unsigned version, void *datav, size_t *data_len) {
    unsigned char ch = tls_pipe_ENCRYPT;
    unsigned char *data = datav;
    char offset;
    (void) cc;
    if (pipe_write(tls_pipe_tochild, &ch, sizeof ch) == -1) goto cleanup;
    if (pipe_write(tls_pipe_tochild, &record_type, sizeof record_type) == -1) goto cleanup;
    if (pipe_write(tls_pipe_tochild, &version, sizeof version) == -1) goto cleanup;
    if (pipe_write(tls_pipe_tochild, data, *data_len) == -1) goto cleanup;
    /* max overhead for TLS-1.1+, CBC AES256+SHA-384 is 85 */
    *data_len += 85;
    if (pipe_readall(tls_pipe_fromchild, &offset, sizeof offset) == -1) goto cleanup;
    if (pipe_readmax(tls_pipe_fromchild, data + offset, data_len) == -1) goto cleanup;
    return data + offset;
cleanup:
    log_e1("encrypt failed");
    /* XXX */
    return data;
}

static void out_chapol_init(const br_sslrec_out_class **cc, br_chacha20_run ichacha, br_poly1305_run ipoly, const void *key, const void *iv) {
    br_sslrec_chapol_context *ctx = (br_sslrec_chapol_context *)cc;
    (void) ichacha;
    (void) ipoly;
    (void) key;
    (void) iv;
    log_t1("out_chapol_init");
    ctx->vtable.out = &tls_pipe_chapol_out_vtable;
}

static void
out_gcm_init(br_sslrec_gcm_context *cc,
    const br_block_ctr_class *bc_impl,
    const void *key, size_t key_len,
    br_ghash gh_impl,
    const void *iv)
{
    (void) bc_impl; (void) key; (void) key_len; (void) gh_impl; (void) iv;
    cc->vtable.out = &tls_pipe_gcm_out_vtable;
}

static void
out_cbc_init(br_sslrec_out_cbc_context *cc,
    const br_block_cbcenc_class *bc_impl,
    const void *bc_key, size_t bc_key_len,
    const br_hash_class *dig_impl,
    const void *mac_key, size_t mac_key_len, size_t mac_out_len,
    const void *iv) {

    log_d1("out_cbc_init");
    cc->vtable = &tls_pipe_cbc_out_vtable;
    cc->seq = 0;
    bc_impl->init(&cc->bc.vtable, bc_key, bc_key_len);
    br_hmac_key_init(&cc->mac, dig_impl, mac_key, mac_key_len);
    cc->mac_len = mac_out_len;
    if (iv == NULL) {
        memset(cc->iv, 0, sizeof cc->iv);
        cc->explicit_IV = 1;
    } else {
        memcpy(cc->iv, iv, bc_impl->block_size);
        cc->explicit_IV = 0;
    }
}

const br_sslrec_out_chapol_class tls_pipe_chapol_out_vtable = {
    {
        sizeof(br_sslrec_chapol_context),
        (void (*)(const br_sslrec_out_class *const *, size_t *, size_t *)) &chapol_max_plaintext,
        (unsigned char *(*)(const br_sslrec_out_class **, int, unsigned, void *, size_t *)) &encrypt
    },
    (void (*)(const br_sslrec_out_chapol_class **, br_chacha20_run, br_poly1305_run, const void *, const void *)) &out_chapol_init
};

const br_sslrec_out_gcm_class tls_pipe_gcm_out_vtable = {
    {
        sizeof(br_sslrec_gcm_context),
        (void (*)(const br_sslrec_out_class *const *,
            size_t *, size_t *))
            &gcm_max_plaintext,
        (unsigned char *(*)(const br_sslrec_out_class **,
            int, unsigned, void *, size_t *))
            &encrypt
    },
    (void (*)(const br_sslrec_out_gcm_class **,
        const br_block_ctr_class *, const void *, size_t,
        br_ghash, const void *))
        &out_gcm_init
};

const br_sslrec_out_cbc_class tls_pipe_cbc_out_vtable = {
    {
        sizeof(br_sslrec_out_cbc_context),
        (void (*)(const br_sslrec_out_class *const *,
            size_t *, size_t *))
            &cbc_max_plaintext,
        (unsigned char *(*)(const br_sslrec_out_class **,
            int, unsigned, void *, size_t *))
            &encrypt
    },
    (void (*)(const br_sslrec_out_cbc_class **,
        const br_block_cbcenc_class *, const void *, size_t,
        const br_hash_class *, const void *, size_t, size_t,
        const void *))
        &out_cbc_init
};
