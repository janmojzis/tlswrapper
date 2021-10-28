#include <unistd.h>
#include "tls.h"
#include "writeall.h"

struct tls_pem ctx = {0};
unsigned char key[32];

int main(int argc, char **argv) {

    (void) argc;
    if (!argv[0]) _exit(100);
    if (!argv[1]) _exit(100);

    if (!tls_pem_load(&ctx, argv[1], key)) _exit(111);
    tls_pem_decrypt(&ctx, key);
    if (writeall(1, ctx.pub, ctx.publen) == -1) _exit(111);

    _exit(0);
}
