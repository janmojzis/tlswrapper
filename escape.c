#include <unistd.h>
#include "e.h"
#include "writeall.h"

static char ibuf[1024];
static long long ibuflen = 0;
static char obuf[4 * sizeof ibuf + 1];
static long long obuflen = 0;

int main(void) {

    long long i;
    char x;

    for (;;) {
        ibuflen = read(0, ibuf, sizeof ibuf);
        if (ibuflen == 0) break;
        if (ibuflen == -1) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;
            if (errno == EWOULDBLOCK) continue;
            _exit(111);
        }
        for (i = 0; i < ibuflen; ++i) {
            x = ibuf[i];
            if (x == 0) {
                obuf[obuflen++] = '\\';
                obuf[obuflen++] = '0';
            }
            else if (x == '\n') {
                obuf[obuflen++] = '\\';
                obuf[obuflen++] = 'n';
            }
            else if (x == '\r') {
                obuf[obuflen++] = '\\';
                obuf[obuflen++] = 'r';
            }
            else if (x < 32 || x > 126) {
                obuf[obuflen++] = '\\';
                obuf[obuflen++] = 'x';
                obuf[obuflen++] = "0123456789abcdef"[(x >> 4) & 15];
                obuf[obuflen++] = "0123456789abcdef"[(x     ) & 15];
            }
            else {
                obuf[obuflen++] = ibuf[i];
            }
        }

        obuf[obuflen++] = '\n';
        if (writeall(1, obuf, obuflen) == -1) _exit(111);
        obuflen = 0;
        ibuflen = 0;
    }
    _exit(0);
}
