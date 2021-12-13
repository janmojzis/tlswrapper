#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "randombytes.h"
#include "log.h"
#include "alloc.h"
#include "tls.h"
#include "fsyncfile.h"
#include "writeall.h"

static struct tls_pem pem = {0};
static struct tls_pubcrt crt = {0};
static struct tls_seccrt keycrt = {0};
static unsigned char key[32];

static int flagverbose = 1;
static int flagpublic = 0;
static int flagsecret = 0;

static const char *fnin = 0;
static const char *fnout = 0;
static int fdout = 1;

static int die(int x) {

    tls_pem_free(&pem);
    randombytes(&crt, sizeof crt);
    randombytes(&keycrt, sizeof keycrt);
    randombytes(key, sizeof key);
    alloc_freeall();
    {
        unsigned char stack[4096];
        randombytes(stack, sizeof stack);
    }
    if (x != 0 && fnout) {
        (void) unlink(fnout);
    }

    _exit(x);
}

static void usage(void) {
    log_u1("tlswrapper-loadpem usage: tlswrapper-loadpem [ -qQvpPsS ] [ -o filename ] -i filename");
    die(100);
}

int main(int argc, char **argv) {

    char *x;

    log_name("tlswrapper-loadpem");

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
            if (*x == 'p') { flagpublic = 1; continue; }
            if (*x == 'P') { flagpublic = 0; continue; }
            if (*x == 's') { flagsecret = 1; continue; }
            if (*x == 'S') { flagsecret = 0; continue; }
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


    if (flagpublic) {
        if (!tls_pubcrt_parse(&crt, pem.pub, pem.publen)) {
            log_f2("unable to parse PEM public-object from the file ", fnin);
            die(111);
        }
        if (writeall(fdout, pem.pub, pem.publen) == -1) {
            log_f2("unable to write output to the file ", fnout);
            die(111);
        }
    }

    if (flagsecret) {
        tls_pem_decrypt(&pem, key);
        if (!tls_seccrt_parse(&keycrt, pem.sec, pem.seclen, fnin)) {
            log_f2("unable to parse PEM secret-object from the file ", fnin);
            die(111);
        }

        if (writeall(fdout, pem.sec, pem.seclen) == -1) {
            log_f2("unable to write output to the file ", fnout);
            die(111);
        }
    }

    if (fsyncfile(fdout) == -1 || close(fdout) == -1) {
        log_f2("unable to write output to the file ", fnout);
        die(111);
    }

    die(0);
    return 0; /* make compiler happy */
}
