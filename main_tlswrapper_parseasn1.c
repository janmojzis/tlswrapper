#include <unistd.h>
#include "tls.h"
#include "log.h"
#include "alloc.h"
#include "randombytes.h"

static unsigned char key[32];
static struct tls_pem pem;
static struct tls_pubcrt crt;
static br_x509_minimal_context ctx;
static br_name_element name;
static char namebuf[256];

static int die(int x) {

    randombytes(key, sizeof key);
    tls_pem_free(&pem);
    randombytes(&crt, sizeof crt);
    randombytes(&ctx, sizeof ctx);
    alloc_freeall();
    {
        unsigned char stack[4096];
        randombytes(stack, sizeof stack);
    }
    _exit(x);
}

int main_tlswrapper_parseasn1(int argc, char **argv) {

    unsigned int status;

    (void)argc;

    if (!argv[0]) die(100);
    if (!argv[1]) die(100);

    log_name("tlswrapper-parseasn1");
    log_level(3);

    randombytes(key, sizeof key);

    if (!tls_pem_load(&pem, argv[1], key)) {
        log_f2("unable to load pem file ", argv[1]);
        die(111);
    }
    if (!tls_pubcrt_parse(&crt, pem.pub, pem.publen)) {
        log_f2("unable to parse PEM public-object from the file ", argv[1]);
        die(111);
    }

    br_x509_minimal_init(&ctx, &br_sha256_vtable, 0, 0);
    br_x509_minimal_set_hash(&ctx, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_hash(&ctx, br_sha384_ID, &br_sha384_vtable);
    br_x509_minimal_set_hash(&ctx, br_sha512_ID, &br_sha512_vtable);
    br_x509_minimal_set_rsa(&ctx, br_rsa_pkcs1_vrfy_get_default());
    br_x509_minimal_set_ecdsa(&ctx, br_ec_get_default(), br_ecdsa_vrfy_asn1_get_default());

    name.oid= (unsigned char *)"\003\125\004\006"; /* countryName */
    name.oid= (unsigned char *)"\011\052\206\110\206\367\015\001\011\001"; /* emailAddress */
    name.oid= (unsigned char *)"\3\125\35\21"; /* subjectAltName */
    name.oid= (unsigned char *)"\003\125\004\003"; /* commonName */
    name.buf = namebuf;
    name.len = sizeof(namebuf);
    br_x509_minimal_set_name_elements(&ctx, &name, 1);
    /* br_x509_minimal_set_time(&ctx, 737865, 0); */

    ctx.vtable->start_chain(&ctx.vtable, 0);
    ctx.vtable->start_cert(&ctx.vtable, crt.crt[0].data_len);
    ctx.vtable->append(&ctx.vtable, crt.crt[0].data, crt.crt[0].data_len);
    ctx.vtable->end_cert(&ctx.vtable);
    ctx.vtable->end_cert(&ctx.vtable);
    status = ctx.vtable->end_chain(&ctx.vtable);
    if (status != BR_ERR_X509_NOT_TRUSTED) {
        log_f2("wrong status: ", lognum(status));
        die(111);
    }
    log_i1(namebuf);
    return 0;
}
