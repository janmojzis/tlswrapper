#include <unistd.h>
#include "randombytes.h"
#include "log.h"
#include "tls.h"
#include "writeall.h"

struct tls_pem ctx = {0};
unsigned char key[32];

void usage(void) {
    log_u1("tlswrapper-loadpem usage: tlswrapper-loadpem filename");
    _exit(100);
}


int main_tlswrapper_loadpem(int argc, char **argv) {

    log_name("tlswrapper-loadpem");
    log_level(1);

    (void) argc;
    if (!argv[0]) usage();
    if (!argv[1]) usage();

    log_level(4);

    randombytes(key, sizeof key);

    if (!tls_pem_load(&ctx, argv[1], key)) {
        log_f2("unable to load pem file ", argv[1]);
        _exit(111);
    }
    /* tls_pem_decrypt(&ctx, key); */
    if (writeall(1, ctx.pub, ctx.publen) == -1) {
        log_f1("unable to write output");
        _exit(111);
    }

    _exit(0);
}
