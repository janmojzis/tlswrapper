#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "log.h"
#include "randombytes.h"
#include "bearssl.h"
#include "fsyncfile.h"
#include "writeall.h"
#include "tls.h"
#include "main.h"

static int flagverbose = 1;
static int flaginput = 0;
static int flagoutput = 0;
static int flagflush = 1;

static int fromchild[2] = {-1, -1};
static int tochild[2] = {-1, -1};
static pid_t child = -1;
static int childstatus;

static br_ssl_client_context sc;
static br_ssl_client_context *cc = &sc;
static br_x509_minimal_context xc;
static br_x509_minimal_context *xcp = &xc;
static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
static br_sslio_context ioc;
static const char *host = 0;
static unsigned char buf[16384];

static char *daysstr = 0;
static unsigned long long days = 0;

static const char *anchorfn = 0;
static unsigned char anchorkey[32] = {0};
static struct tls_pem anchorpem = {0};
static struct tls_pubcrt anchorcrt = {0};

static const char *ppstring = 0;

static int numparse(unsigned long long *num, const char *x) {

    char *endptr = 0;

    *num = strtoull(x, &endptr, 10);

    if (!x || strlen(x) == 0 || !endptr || endptr[0]) {
        return 0;
    }
    return 1;
}

static int _read(void *ctx, unsigned char *buf, size_t len) {

    int r;

    for (;;) {
        r = read(*(int *)ctx, buf, len);
        if (r == 0) errno = EPIPE;
        if (r <= 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        return r;
    }
}

static int _write(void *ctx, const unsigned char *buf, size_t len) {

    int w;

    for (;;) {
        w = write(*(int *)ctx, buf, len);
        if (w == 0) errno = EPIPE;
        if (w <= 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        return w;
    }
}


static unsigned int my_end_chain(const br_x509_class **ctx) {
    unsigned int r;

    r = br_x509_minimal_vtable.end_chain(ctx);
    if (r == BR_ERR_X509_NOT_TRUSTED) {
        r = 0;
    }
    return 0;
}

static br_x509_class my509vtable;
static const br_x509_class *getvtable(void) {
    memcpy(&my509vtable, &br_x509_minimal_vtable, sizeof br_x509_minimal_vtable);
    my509vtable.end_chain = my_end_chain;
    return &my509vtable;
}

static void cleanup(void) {
    {
        unsigned char stack[4096];
        randombytes(stack, sizeof stack);
    }
}

#define die(x) { cleanup(); _exit(x); }
#define die_pipe() { log_f1("unable to create pipe"); die(111); }
#define die_fork() { log_f1("unable to fork"); die(111); }
#define die_dup() { log_f1("unable to dup"); die(111); }
#define die_setenv(x) { log_f2("unable to set env. variable ", (x)); die(111); }
#define die_parseanchorpem(x) { log_f3("unable to parse anchor PEM file '", (x), "'"); die(111); }
#define die_loadpem(x) { log_f2("unable to load pem file ", (x)); die(111); }
#define die_parsepem(x) { log_f2("unable to parse PEM public-object from the file ", (x)); die(111); }
#define die_write() { log_f1("unable to write output"); die(111); }

static void usage(void) {
    log_u1("tlswrapper-test [options] prog");
    die(100);
}

int main_tlswrapper_test(int argc, char **argv) {

    char *x;
    long long r;

    signal(SIGPIPE, SIG_IGN);
    log_name("tlswrapper-test");
    log_id("");

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
            if (*x == 'r') { flaginput = 1; flagoutput = 0; continue; }
            if (*x == 'w') { flagoutput = 1; flaginput = 0; continue; }
            if (*x == 'f') { flagflush = 1; continue; }
            if (*x == 'F') { flagflush = 0; continue; }
            if (*x == 'P') {
                if (x[1]) { ppstring = (x + 1); break; }
                if (argv[1]) { ppstring = (*++argv); break; }
            }
            if (*x == 'a') {
                if (x[1]) { anchorfn = (x + 1); break; }
                if (argv[1]) { anchorfn = (*++argv); break; }
            }
            if (*x == 'h') {
                if (x[1]) { host = (x + 1); break; }
                if (argv[1]) { host = (*++argv); break; }
            }
            if (*x == 'd') {
                if (x[1]) { daysstr = x + 1; break; }
                if (argv[1]) { daysstr = *++argv; break; }
            }
            usage();
        }
    }
    if (!*++argv) usage();

    if (!flaginput && !flagoutput) {
        log_f1("option -r or -w must be set");
        die(100);
    }

    log_ip("0.0.0.0");
    log_d1("start");

    /* set fake env. variables */
    if (setenv("TCPREMOTEIP", "0.0.0.0", 1) == -1) die_setenv("TCPREMOTEIP");
    if (setenv("TCPREMOTEPORT", "0", 1) == -1) die_setenv("TCPREMOTEPORT");
    if (setenv("TCPLOCALIP", "0.0.0.0", 1) == -1) die_setenv("TCPLOCALIP");
    if (setenv("TCPLOCALPORT", "0", 1) == -1) die_setenv("TCPLOCALPORT");


    /* run child process */
    if (pipe(fromchild) == -1) die_pipe();
    if (pipe(tochild) == -1) die_pipe();
    child = fork();
    switch (child) {
        case -1:
            die_fork();
        case 0:
            close(fromchild[0]);
            close(tochild[1]);
            close(0);
            if (dup(tochild[0]) != 0) die_dup();
            close(1);
            if (dup(fromchild[1]) != 1) die_dup();

            signal(SIGPIPE, SIG_DFL);
            execvp(*argv, argv);
            log_f2("unable to run ", *argv);
            die(111);
    }
    close(fromchild[1]);
    close(tochild[0]);


    /* load and parse anchor PEM file */
    if (anchorfn) {
        if (!tls_pem_load(&anchorpem, anchorfn, anchorkey)) die_loadpem(anchorfn);
        if (!tls_pubcrt_parse(&anchorcrt, anchorpem.pub, anchorpem.publen, anchorfn)) die_parsepem(anchorfn)
    }

    /* initialise the client context */
    br_ssl_client_init_full(&sc, &xc, anchorcrt.ta, anchorcrt.talen);
    if (!anchorfn) {
        xc.vtable = getvtable();
        br_ssl_engine_set_x509(&cc->eng, &xcp->vtable);
    }
    if (daysstr) {
        if (!numparse(&days, daysstr)) {
            log_f3("unable to parse '", daysstr, "'");
            die(100);
        }
        log_t2("days = ", lognum(days));
        br_x509_minimal_set_time(&xc, days, 0);
    }

    /* write proxy-protocol string */
    if (ppstring) {
        if (writeall(tochild[1], ppstring, strlen(ppstring)) == -1) {
            log_f1("unable to write output");
            die(111);
        }
        if (writeall(tochild[1], "\r\n", 2) == -1) {
            log_f1("unable to write output");
            die(111);
        }
    }

    /* set the I/O buffer */
    br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

    /* reset the client context, for a new handshake */
    log_d2("host = ", host);
    br_ssl_client_reset(&sc, host, 0);

    /* initialise the I/O wrapper context */
    br_sslio_init(&ioc, &sc.eng, _read, &fromchild[0], _write, &tochild[1]);


    if (flaginput) {
        for (;;) {
            r = br_sslio_read(&ioc, buf, sizeof buf);
            if (r == -1) {
                log_f1("unable to read from child");
                break;
            }
            if (writeall(1, buf, r) == -1) {
                log_f1("unable to write output");
                die(111);
            }
        }
        if (fsyncfile(1) == -1) die_write();
        if (close(1) == -1) die_write()
    }
    if (flagoutput) {
        for (;;) {
            r = read(0, buf, sizeof buf);
            if (r == -1) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            }
            if (r <= 0) break;
            if (br_sslio_write_all(&ioc, buf, r) == -1) {
                log_f1("unable to write to child");
                break;
            }
        }
        if (flagflush) br_sslio_close(&ioc);
        br_sslio_flush(&ioc);
    }

    close(fromchild[0]);
    close(tochild[1]);

    if (br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED) {
        int err;
        err = br_ssl_engine_last_error(&sc.eng);
        if (err == BR_ERR_OK) {
            log_i1("SSL closed normally");
        }
        else {
            if (err >= BR_ERR_SEND_FATAL_ALERT) {
                err -= BR_ERR_SEND_FATAL_ALERT;
                log_f2("SSL closed abnormally, sent alert: ", tls_error_str(err));
            } else if (err >= BR_ERR_RECV_FATAL_ALERT) {
                err -= BR_ERR_RECV_FATAL_ALERT;
                log_f2("SSL closed abnormally, received alert: ", tls_error_str(err));
            }
            else {
                log_f2("SSL closed abnormally: ", tls_error_str(err));
            }
        }
    }

    while (waitpid(child, &childstatus, 0) != child) {};
    die(WEXITSTATUS(childstatus));

    die(0);
}
