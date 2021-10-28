#include <unistd.h>
#include "randombytes.h"

unsigned char buf[1024];

int main(void) {

    chroot(".");
    randombytes(buf, sizeof buf);
    write(1, buf, sizeof buf);
    return 0;
}
