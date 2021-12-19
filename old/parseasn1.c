#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "tls.h"
#include "log.h"
#include "alloc.h"
#include "fsyncfile.h"
#include "writeall.h"
#include "randombytes.h"

static unsigned char key[32] = {0};
static struct tls_pem pem = {0};
static struct tls_pubcrt crt = {0};
static br_x509_minimal_context ctx = {0};
static br_name_element name = {0};
static char namebuf[256] = {0};
static long long namebuflen = 0;

static int flagverbose = 1;

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

static void usage(void) {
    log_u1("tlswrapper-parseasn1 usage: tlswrapper-parseasn1 [ -qQv ] [ -o filename ] -d [ days ] -i filename object");
    die(100);
}

static const char *fnin = 0;
static const char *fnout = 0;
static int fdout = 1;

static unsigned int status;
static const char *object;


static int numparse(unsigned long long *num, const char *x) {

    char *endptr = 0;

    *num = strtoull(x, &endptr, 10);

    if (!x || strlen(x) == 0 || !endptr || endptr[0]) {
        return 0;
    }
    return 1;
}

static char *daysstr = 0;
static unsigned long long days = 0;

int main(int argc, char **argv) {

    char *x;

    log_name("tlswrapper-parseasn1");

    (void) argc;
    if (!argv[0]) usage();
    for (;;) {
        if (!argv[1]) break;
        if (argv[1][0] != '-') break;
        x = *++argv;
        if (x[0] == '-' && x[1] == 0) break;
        if (x[0] == '-' && x[1] == '-' && x[2] == 0) break;
        while (*++x) {
            if (*x == 'q') { flagverbose = 0; log_level(flagverbose); continue; }
            if (*x == 'Q') { flagverbose = 1; log_level(flagverbose); continue; }
            if (*x == 'v') { log_level(++flagverbose); continue; }
            if (*x == 'd') {
                if (x[1]) { daysstr = x + 1; break; }
                if (argv[1]) { daysstr = *++argv; break; }
            }
            if (*x == 'i') {
                if (x[1]) { fnin = x + 1; break; }
                if (argv[1]) { fnin = *++argv; break; }
            }
            if (*x == 'o') {
                if (x[1]) { fnout = x + 1; break; }
                if (argv[1]) { fnout = *++argv; break; }
            }
            usage();
        }
    }
    log_time(1);

    object = *++argv;
    if (!object) usage();

    if (!strcmp("commonName", object)) {
        name.oid = (unsigned char *)"\003\125\004\003";
    }
    else if (!strcmp("emailAddress", object)) {
        name.oid = (unsigned char *)"\011\052\206\110\206\367\015\001\011\001";
    }
    else if (!strcmp("countryName", object)) {
        name.oid= (unsigned char *)"\003\125\004\006";
    }
    else if (!strcmp("organizationName", object)) {
        name.oid= (unsigned char *)"\3\125\4\12";
    }
    else if (!strcmp("organizationalUnitName", object)) {
        name.oid= (unsigned char *)"\3\125\4\13";
    }
    else if (!strcmp("localityName", object)) {
        name.oid= (unsigned char *)"\3\125\4\7";
    }
    else if (!strcmp("stateOrProvinceName", object)) {
        name.oid= (unsigned char *)"\3\125\4\10";
    }
    else {
        usage();
    }

    if (!fnin) usage();
    if (!fnout) fnout = "-";
    if (strcmp(fnout, "-")) {
        fdout = open(fnout, O_CREAT | O_WRONLY | O_NONBLOCK, 0644);
        if (fdout == -1) {
            log_f3("unable to open file ", fnout, " for writing");
            die(111);
        }
    }

    randombytes(key, sizeof key);

    if (!tls_pem_load(&pem, fnin, key)) {
        log_f2("unable to load pem file ", fnin);
        die(111);
    }
    if (!tls_pubcrt_parse(&crt, pem.pub, pem.publen, fnin)) {
        log_f2("unable to parse PEM public-object from the file ", fnin);
        die(111);
    }

    br_x509_minimal_init(&ctx, &br_sha256_vtable, 0, 0);
    br_x509_minimal_set_hash(&ctx, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_hash(&ctx, br_sha384_ID, &br_sha384_vtable);
    br_x509_minimal_set_hash(&ctx, br_sha512_ID, &br_sha512_vtable);
    br_x509_minimal_set_rsa(&ctx, br_rsa_pkcs1_vrfy_get_default());
    br_x509_minimal_set_ecdsa(&ctx, br_ec_get_default(), br_ecdsa_vrfy_asn1_get_default());
    if (daysstr) {
        if (!numparse(&days, daysstr)) {
            log_f3("unable to parse '", daysstr, "'");
            die(100);
        }
        log_t2("days = ", lognum(days));
        br_x509_minimal_set_time(&ctx, days, 0);
    }

    name.buf = namebuf;
    name.len = sizeof(namebuf);
    br_x509_minimal_set_name_elements(&ctx, &name, 1);

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
    namebuf[sizeof namebuf - 1] = 0;
    log_d1(namebuf);
    namebuflen = strlen(namebuf);
    namebuf[namebuflen] = '\n';

    if (writeall(fdout, namebuf, namebuflen + 1) == -1) {
        log_f2("unable to write output to the file ", fnout);
        die(111);
    }

    if (fsyncfile(fdout) == -1 || close(fdout) == -1) {
        log_f2("unable to write output to the file ", fnout);
        die(111);
    }

    die(0);
    return 0; /* make compiler happy */
}
