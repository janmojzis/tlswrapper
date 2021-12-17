#include "log.h"
#include "tls.h"
#include "randombytes.h"

static char idbuf[17];
void tls_logsessionid(const br_ssl_engine_context *cc) {

    br_ssl_session_parameters sp;
    unsigned char *y;
    unsigned long long i;

    br_ssl_engine_get_session_parameters(cc, &sp);
    y = sp.session_id;

    for (i = 0; i < sizeof idbuf / 2; ++i) {
        idbuf[2 * i    ] = "0123456789abcdef"[(y[i] >> 4) & 15];
        idbuf[2 * i + 1] = "0123456789abcdef"[(y[i] >> 0) & 15];
    }
    idbuf[2 * i] = 0;
    log_id(idbuf);
    randombytes(&sp, sizeof sp);
}
