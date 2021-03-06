#include <unistd.h>
#include "e.h"
#include "log.h"
#include "writeall.h"

static char ibuf[1024];
static long long ibuflen = 0;
static char obuf[4 * sizeof ibuf + 1];
static long long obuflen = 0;

int main(void) {

    long long i;
    char x;

    log_name("escape");
    log_level(2);

    log_i1("start");

    for (;;) {
        ibuflen = read(0, ibuf, sizeof ibuf);
        if (ibuflen == 0) break;
        if (ibuflen == -1) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;
            if (errno == EWOULDBLOCK) continue;
            log_f1("unable to read from input");
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
                obuf[obuflen++] = "0123456789abcdef"[(x >> 0) & 15];
            }
            else {
                obuf[obuflen++] = ibuf[i];
            }
        }
        if (writeall(1, obuf, obuflen) == -1) {
            log_f1("unable write to output");
            _exit(111);
        }
        obuflen = 0;
        ibuflen = 0;
    }
    if (writeall(1, "\n", 1) == -1) {
        log_f1("unable write to output");
        _exit(111);
    }
    _exit(0);
}
