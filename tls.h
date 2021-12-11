#ifndef _TLS_H____
#define _TLS_H____

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "bearssl.h"

#define tls_MAXCERTFILES 16

struct tls_pubcrt {

    /* crt */
    char key_type;  /* BR_KEYTYPE_RSA or BR_KEYTYPE_EC */
    br_x509_certificate crt[tls_MAXCERTFILES];
    size_t crtlen;

    /* ta */
    br_x509_trust_anchor ta[tls_MAXCERTFILES];
    size_t talen;
};

struct tls_seccrt {

    const void *key;
    char key_type;  /* BR_KEYTYPE_RSA or BR_KEYTYPE_EC */
    br_skey_decoder_context keydc;
};

struct tls_certfile {
    const char *name;
    mode_t filetype;
};

#define tls_CERTFILES 4

struct tls_context {
    const br_ssl_server_policy_class *vtable;
    br_x509_certificate chain[tls_MAXCERTFILES];
    size_t chain_len;
    char key_type;

    br_ssl_server_context cc;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
    uint32_t flags;

    /* anchor */
    br_x509_minimal_context xc;
    const char *anchorfn;
    const char *anchorpem;
    size_t anchorpemlen;
    struct tls_pubcrt anchorcrt;
    br_name_element clientcrt;
    char clientcrtbuf[256];

    struct tls_certfile certfiles[tls_CERTFILES];
    size_t certfiles_len;

    struct tls_pubcrt crt;

    const char *jailaccount;

    const char *jaildir;

    unsigned int version_min;
    unsigned int version_max;

    uint32_t ecdhe_enabled;
    const br_ec_impl ecdhe_copy;

    size_t cipher_enabled_len;
    uint16_t cipher_enabled[16];
};

/* flags */
#define tls_flags_ENFORCE_SERVER_PREFERENCES (BR_OPT_ENFORCE_SERVER_PREFERENCES)
#define tls_flags_NO_RENEGOTIATION (BR_OPT_NO_RENEGOTIATION)
#define tls_flags_TOLERATE_NO_CLIENT_AUTH (BR_OPT_TOLERATE_NO_CLIENT_AUTH)

/* tls_profile.c */
extern void tls_profile(struct tls_context *);

/* tls_error.c */
extern const char *tls_error_str(int);

/* tls_keytype.c */
extern const char *tls_keytype_str(int);

/* tls_version.c */
typedef struct {
    const char *name;
    unsigned int version;
    const char *comment;
} tls_version;
extern const tls_version tls_versions[];
#define tls_version_TLS10 BR_TLS10
#define tls_version_TLS11 BR_TLS11
#define tls_version_TLS12 BR_TLS12
extern int tls_version_setmin(struct tls_context *, const char *);
extern int tls_version_setmax(struct tls_context *, const char *);
extern const char *tls_version_str(unsigned int);

/* tls_ecdhe.c */
typedef struct {
    const char *name;
    uint32_t curve;
} tls_ecdhe;
extern const tls_ecdhe tls_ecdhes[];
#define tls_ecdhe_X25519    BR_EC_curve25519
#define tls_ecdhe_X448      BR_EC_curve448
#define tls_ecdhe_SECP256R1 BR_EC_secp256r1
#define tls_ecdhe_SECP384R1 BR_EC_secp384r1
#define tls_ecdhe_SECP521R1 BR_EC_secp521r1
extern const char *tls_ecdhe_str(unsigned char);
extern const br_ec_impl *tls_ecdhe_get_default(struct tls_context *);
extern int tls_ecdhe_add(struct tls_context *, const char *);

/* tls_cipher.c */
typedef struct {
    const char *name;
    uint16_t ecsuite;
    uint16_t rsasuite;
    const char *eccomment;
    const char *rsacomment;
} tls_cipher;
extern const tls_cipher tls_ciphers[];
extern int tls_cipher_add(struct tls_context *, const char *);
extern const char *tls_cipher_str(uint16_t);

/* tls_crypto_scalarmult.c */
#define tls_crypto_scalarmult_MAXSCALARBYTES 66
#define tls_crypto_scalarmult_MAXBYTES 133
extern int tls_crypto_scalarmult_base(int, unsigned char *, size_t *, unsigned char *);
extern int tls_crypto_scalarmult(int, unsigned char *, size_t *, unsigned char *);

/* tls_keyjail.c */
extern void tls_keyjail(struct tls_context *);

/* tls_pipe.c */
extern int tls_pipe_fromchild;
extern int tls_pipe_tochild;
extern br_ssl_engine_context *tls_pipe_eng;
extern int tls_pipe_getcert(br_x509_certificate *, size_t *, char *, const char *, const char *);
extern size_t tls_pipe_dosign(const br_ssl_server_policy_class **, unsigned int, unsigned char *, size_t, size_t);
extern size_t tls_pipe_mulgen(unsigned char *, const unsigned char *, size_t, int);
extern uint32_t tls_pipe_mul(unsigned char *, size_t, const unsigned char *, size_t, int);
extern void tls_pipe_prf(void *, size_t, const void *, size_t, const char *, size_t, const br_tls_prf_seed_chunk *);
#define tls_pipe_PRF 0
#define tls_pipe_DECRYPT 1
#define tls_pipe_ENCRYPT 2
extern const br_sslrec_in_chapol_class tls_pipe_chapol_in_vtable;
extern const br_sslrec_out_chapol_class tls_pipe_chapol_out_vtable;
extern const br_sslrec_in_gcm_class tls_pipe_gcm_in_vtable;
extern const br_sslrec_out_gcm_class tls_pipe_gcm_out_vtable;
extern const br_sslrec_in_cbc_class tls_pipe_cbc_in_vtable;
extern const br_sslrec_out_cbc_class tls_pipe_cbc_out_vtable;

/* tls_certfile.c */
extern int tls_certfile_add_dir(struct tls_context *, const char *);
extern int tls_certfile_add_file(struct tls_context *, const char *);

/* tls_pem.c */
struct tls_pem {
    unsigned long long alloc;
    /* public part - CERTIFICATE */
    size_t publen;
    char *pub;
    /* secret part - KEY */
    size_t seclen;
    char *sec;
};
extern void tls_pem_free(struct tls_pem *);
extern int tls_pem_load(struct tls_pem *, const char *, const unsigned char *);
extern void tls_pem_encrypt(struct tls_pem *, const unsigned char *);
#define tls_pem_decrypt tls_pem_encrypt

/* tls_pubcrt.c */
extern int tls_pubcrt_parse(struct tls_pubcrt *, const char *, size_t);

/* tls_seccrt.c */
extern int tls_seccrt_parse(struct tls_seccrt *, const char *, size_t);

/* tls_ecdsa.c */
extern uint32_t tls_ecdsa_vrfy_asn1(const br_ec_impl *, const void *, size_t, const br_ec_public_key *, const void *, size_t);

/* tls_timeout.c */
extern int tls_timeout_parse(long long *, const char *);

/* tls_anchor.c */
extern int tls_anchor_add(struct tls_context *, const char *);

#endif
