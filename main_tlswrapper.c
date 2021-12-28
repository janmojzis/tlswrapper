#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include "blocking.h"
#include "pipe.h"
#include "log.h"
#include "e.h"
#include "jail.h"
#include "randombytes.h"
#include "alloc.h"
#include "connectioninfo.h"
#include "proxyprotocol.h"
#include "iptostr.h"
#include "writeall.h"
#include "fixname.h"
#include "fixpath.h"
#include "tls.h"
#include "main.h"

/* clang-format off */

static struct tls_context ctx = {
    .flags = (tls_flags_ENFORCE_SERVER_PREFERENCES | tls_flags_NO_RENEGOTIATION),
    .flagnojail = 0,
    .jailaccount = 0,
    .jaildir = EMPTYDIR,
    .version_min = tls_version_TLS12,
    .version_max = tls_version_TLS12,
    .ecdhe_enabled = ((uint32_t) 1 << tls_ecdhe_X25519) | ((uint32_t) 1 << tls_ecdhe_SECP256R1),
    .cipher_enabled_len = 6,
    .certfiles_len = 0,
    .anchorfn = 0,
    .clientcrtbuf = {0},
    .clientcrt.oid = 0,
    .cipher_enabled = {
        BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        /* space for ECDSA AES_256_CBC_SHA384 */ 0,
        /* space for RSA AES_256_CBC_SHA384 */ 0,
        /* space for ECDSA AES_128_CBC_SHA256 */ 0,
        /* space for RSA AES_128_CBC_SHA256 */ 0,
        /* space for ECDSA AES_256_CBC_SHA */ 0,
        /* space for RSA AES_256_CBC_SHA */ 0,
        /* space for ECDSA AES_128_CBC_SHA */ 0,
        /* space for RSA AES_128_CBC_SHA */ 0,
    },
};

static const char *hstimeoutstr = "30";
static const char *timeoutstr = "3600";
static const char *user = 0;
static const char *userfromcert = 0;

static long long starttimeout = 3;
static long long hstimeout;
static long long timeout;

static int flagverbose = 1;

static int fromchild[2] = {-1, -1};
static int tochild[2] = {-1, -1};
static pid_t child = -1;
static int status;

static int fromkeyjail[2] = {-1, -1};
static int tokeyjail[2] = {-1, -1};
static pid_t keyjailchild = -1;

static int selfpipe[2] = {-1, -1};

static unsigned char localip[16] = {0};
static unsigned char localport[2] = {0};
static unsigned char remoteip[16] = {0};
static unsigned char remoteport[2] = {0};
static char remoteipstr[IPTOSTR_LEN] = {0};

static void signalhandler(int signum) {
    int w;
    log_t3("signal ", lognum(signum), " received");
    if (signum == SIGCHLD) {
        alarm(1);
        return;
    }
    w = write(selfpipe[1], "", 1);
    (void) w;
}

static void cleanup(void) {
    randombytes(&ctx, sizeof ctx);
    randombytes(localip, sizeof localip);
    randombytes(localport, sizeof localport);
    randombytes(remoteip, sizeof remoteip);
    randombytes(remoteip, sizeof remoteip);
    randombytes(remoteipstr, sizeof remoteipstr);
    alloc_freeall();
    {
        unsigned char stack[4096];
        randombytes(stack, sizeof stack);
    }
}

#define die(x) { cleanup(); _exit(x); }
#define die_pipe() { log_f1("unable to create pipe"); die(111); }
#define die_writetopipe() { log_f1("unable to write to pipe"); die(111); }
#define die_fork() { log_f1("unable to fork"); die(111); }
#define die_dup() { log_f1("unable to dup"); die(111); }
#define die_droppriv(x) { log_f3("unable to drop privileges to '", (x), "'"); die(111); }
#define die_jail() { log_f1("unable to create jail"); die(111); }
#define die_readanchorpem(x) { log_f3("unable to read anchor PEM file '", (x), "'"); die(111); }
#define die_parseanchorpem(x) { log_f3("unable to parse anchor PEM file '", (x), "'"); die(111); }
#define die_extractcn(x) { log_f3("unable to extract ASN.1 object ", (x), " from client certificate: object not found"); die(111); }
#define die_optionUa() { log_f1("option -U must be used with -a"); die(100); }
#define die_ppout(x) { log_f3("unable to create outgoing proxy-protocol v", (x), " string");; die(100); }
#define die_ppin(x) { log_f3("unable to receive incoming proxy-protocol v", (x), " string");; die(100); }


/* proxy-protocol */
static long long (*ppout)(char *, long long, unsigned char *, unsigned char *, unsigned char *, unsigned char *) = 0;
static const char *ppoutver = 0;
static int (*ppin)(int, unsigned char *, unsigned char *, unsigned char *, unsigned char *) = 0;
static const char *ppinver = 0;

static void pp_incoming(const char *x) {

    if (!strcmp("0", x)) {
        /* disable incoming proxy-protocol*/
        return;
    }
    else if (!strcmp("1", x)) {
        ppin = proxyprotocol_v1_get;
        ppinver = x;
    }
    else {
        log_f3("unable to parse incoming proxy-protocol version from the string '", x, "'");
        log_f1("available: 1");
        die(100);
    }
}
static void pp_outgoing(const char *x) {

    if (!strcmp("0", x)) {
        /* disable outgoing proxy-protocol */
        return;
    }
    else if (!strcmp("1", x)) {
        ppout = proxyprotocol_v1;
        ppoutver = x;
    }
    else if (!strcmp("2", x)) {
        ppout = proxyprotocol_v2;
        ppoutver = x;
    }
    else {
        log_f3("unable to parse outgoing proxy-protocol version from the string '", x, "'");
        log_f1("available: 1");
        log_f1("available: 2");
        die(100);
    }
}
static void certuser_add(const char *x) {

    userfromcert = x;
    if (!strcmp("commonName", x)) {
        ctx.clientcrt.oid = (unsigned char *)"\003\125\004\003";
    }
    else if (!strcmp("emailAddress", x)) {
        ctx.clientcrt.oid = (unsigned char *)"\011\052\206\110\206\367\015\001\011\001";
    }
    else {
        log_f3("unable to parse ASN.1 object from the string '", x, "'");
        log_f1("available: commonName");
        log_f1("available: emailAddress");
        die(100);
    }
}
static void version_setmax(const char *x) {

    long long i;

    if (!tls_version_setmax(&ctx, x)) {
        log_f3("unable to parse TLS max. version from the string '", x, "'");
        for (i = 0; tls_versions[i].name; ++i) {
            log_f2("available: ", tls_versions[i].name);
        }
        die(100);
    }
}
static void version_setmin(const char *x) {

    long long i;

    if (!tls_version_setmin(&ctx, x)) {
        log_f3("unable to parse TLS min. version from the string '", x, "'");
        for (i = 0; tls_versions[i].name; ++i) {
            log_f2("available: ", tls_versions[i].name);
        }
        die(100);
    }
}
static void certfile_add_dir(const char *x) {

    struct stat st;

    if (stat(x, &st) == -1) {
        log_f3("unable to stat certdir '", x, "'");
        die(100)
    }
    if ((st.st_mode & S_IFMT) != S_IFDIR) {
        errno = ENOTDIR;
        log_f3("unable to add certdir '", x, "'");
        die(100)
    }
    if (!tls_certfile_add_dir(&ctx, x)) {
        log_f3("unable to add more than ", lognum(tls_CERTFILES), " certdirs+certfiles");
        die(100);
    }
}
static void certfile_add_file(const char *x) {

    struct stat st;

    if (stat(x, &st) == -1) {
        log_f3("unable to stat certfile '", x, "'");
        die(100);
    }
    if ((st.st_mode & S_IFMT) != S_IFREG) {
        errno = 0;
        log_f3("unable to add certfile '", x, "': not a regular file");
        die(100);
    }
    if (!tls_certfile_add_file(&ctx, x)) {
        log_f3("unable to add more than ", lognum(tls_CERTFILES), " certdirs+certfiles");
        die(100);
    }
}
static void anchor_add(char *x) {
    struct stat st;

    if (stat(x, &st) == -1) {
        log_f3("unable to add anchor file '", x, "'");
        die(100);
    }
    if ((st.st_mode & S_IFMT) != S_IFREG) {
        errno = 0;
        log_f3("unable to add anchor file '", x, "': not a regular file");
        die(100);
    }
    if (!tls_anchor_add(&ctx, x)) {
        log_f1("unable to add more than one anchor file");
        die(100);
    }
}
static void ecdhe_add(const char *x) {

    long long i;

    if (!tls_ecdhe_add(&ctx, x)) {
        log_f3("unable to parse ephemeral algorithm from the string '", x, "'");
        for (i = 0; tls_ecdhes[i].name; ++i) {
            log_f2("available: ", tls_ecdhes[i].name);
        }
        die(100);
    }
}
static void cipher_add(const char *x) {

    long long i;

    if (!tls_cipher_add(&ctx, x)) {
        log_f3("unable to parse cipher from the string '", x, "'");
        for (i = 0; tls_ciphers[i].name; ++i) {
            log_f2("available: ", tls_ciphers[i].name);
        }
        die(100);
    }
}
static long long timeout_parse(const char *x) {
    long long ret;
    if (!tls_timeout_parse(&ret, x)) {
        log_f3("unable to parse timeout from the string '", x, "'");
        die(100);
    }
    if (ret < 1) {
        log_f3("timeout must be a number > 0, not '", x, "'");
        die(100);
    }
    if (ret > 86400) {
        log_f3("timeout must be a number < 86400, not '", x, "'");
        die(100);
    }
    return ret;
}

static void usage(void) {
    log_u1("tlswrapper [options] [ -d certdir ] [ -f certfile ] prog");
    die(100);
}


int main_tlswrapper(int argc, char **argv, int flagnojail) {

    char *x;
    int handshakedone = 0;
    long long r;

    errno = 0;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, signalhandler);
    signal(SIGTERM, signalhandler);
    alarm(starttimeout);

    log_name("tlswrapper");
    log_id(0);

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

            /* server preferences */
            if (*x == 's') { ctx.flags |= tls_flags_ENFORCE_SERVER_PREFERENCES; continue; }
            if (*x == 'S') { ctx.flags &= ~tls_flags_ENFORCE_SERVER_PREFERENCES; continue; }

            /* proxy-protocol */
            if (*x == 'p') {
                if (x[1]) { pp_incoming(x + 1); break; }
                if (argv[1]) { pp_incoming(*++argv); break; }
            }
            if (*x == 'P') {
                if (x[1]) { pp_outgoing(x + 1); break; }
                if (argv[1]) { pp_outgoing(*++argv); break; }
            }

            /* run child under user */
            if (*x == 'U') {
                if (x[1]) { certuser_add(x + 1); break; }
                if (argv[1]) { certuser_add(*++argv); break; }
            }
            if (*x == 'u') {
                if (x[1]) { user = x + 1; break; }
                if (argv[1]) { user = *++argv; break; }
            }

            /* TLS version */
            if (*x == 'm') {
                if (x[1]) { version_setmin(x + 1); break; }
                if (argv[1]) { version_setmin(*++argv); break; }
            }
            if (*x == 'M') {
                if (x[1]) { version_setmax(x + 1); break; }
                if (argv[1]) { version_setmax(*++argv); break; }
            }

            /* timeouts */
            if (*x == 'T') {
                if (x[1]) { hstimeoutstr =  x + 1; break; }
                if (argv[1]) { hstimeoutstr = *++argv; break; }
            }
            if (*x == 't') {
                if (x[1]) { timeoutstr =  x + 1; break; }
                if (argv[1]) { timeoutstr = *++argv; break; }
            }

            /* certificates */
            if (*x == 'd') {
                if (x[1]) { certfile_add_dir(x + 1); break; }
                if (argv[1]) { certfile_add_dir(*++argv); break; }
            }
            if (*x == 'f') {
                if (x[1]) { certfile_add_file(x + 1); break; }
                if (argv[1]) { certfile_add_file(*++argv); break; }
            }
            /* anchor - client certificates */
            if (*x == 'a') {
                ctx.flags &= ~tls_flags_TOLERATE_NO_CLIENT_AUTH;
                if (x[1]) { anchor_add(x + 1); break; }
                if (argv[1]) { anchor_add(*++argv); break; }
            }

            /* ephemeral */
            if (*x == 'e') {
                if (x[1]) { ecdhe_add(x + 1); break; }
                if (argv[1]) { ecdhe_add(*++argv); break; }
            }

            /* ciphers */
            if (*x == 'c') {
                if (x[1]) { cipher_add(x + 1); break; }
                if (argv[1]) { cipher_add(*++argv); break; }
            }

            /* jail */
            if (*x == 'J') {
                if (x[1]) { ctx.jaildir = (x + 1); break; }
                if (argv[1]) { ctx.jaildir = (*++argv); break; }
            }
            if (*x == 'j') {
                if (x[1]) { ctx.jailaccount = (x + 1); break; }
                if (argv[1]) { ctx.jailaccount = (*++argv); break; }
            }

            usage();
        }
    }
    if (!*++argv) usage();
    if (!ctx.certfiles_len) usage();
    if (userfromcert && !ctx.anchorfn) die_optionUa();
    timeout = timeout_parse(timeoutstr);
    hstimeout = timeout_parse(hstimeoutstr);

    /* set flagnojail */
    ctx.flagnojail = flagnojail;

    /* non-blockning stdin/stdout */
    blocking_disable(0);
    blocking_disable(1);

    /* run child process */
    if (pipe(fromchild) == -1) die_pipe();
    if (pipe(tochild) == -1) die_pipe();
    child = fork();
    switch (child) {
        case -1:
            die_fork();
        case 0:
            alarm(0);
            close(fromchild[0]);
            close(tochild[1]);
            close(0);
            if (dup(tochild[0]) != 0) die_dup();
            close(1);
            if (dup(fromchild[1]) != 1) die_dup();
            blocking_enable(0);
            blocking_enable(1);

            /* read connection info from net-process */
            if (pipe_readall(0, localip, sizeof localip) == -1) die(111);
            if (pipe_readall(0, localport, sizeof localport) == -1) die(111);
            if (pipe_readall(0, remoteip, sizeof remoteip) == -1) die(111);
            if (pipe_readall(0, remoteport, sizeof remoteport) == -1) die(111);
            connectioninfo_set(localip, localport, remoteip, remoteport);

            /* drop root to account from client certificate ASN.1 object */
            do {
                char account[256];
                size_t accountlen = sizeof account;
                if (pipe_readmax(0, account, &accountlen) == -1) die(111);
                if (accountlen <= 1) break;
                account[accountlen - 1] = 0;
                if (!userfromcert) break;
                if (jail_droppriv(account) == -1) die_droppriv(account);
            } while (0);

            /* drop root */
            if (user) if (jail_droppriv(user) == -1) die_droppriv(user);

            signal(SIGPIPE, SIG_DFL);
            signal(SIGCHLD, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            log_t3("running '", argv[0], "'");
            execvp(*argv, argv);
            log_f2("unable to run ", *argv);
            die(111);
    }
    close(fromchild[1]);
    close(tochild[0]);
    blocking_disable(fromchild[0]);
    blocking_disable(tochild[1]);

    /* initialize randombytes */
    {
        char ch[1];
        randombytes(ch, sizeof ch);
    }

    /* run service process for loading keys and secret-key operations */
    if (pipe(fromkeyjail) == -1) die_pipe();
    if (pipe(tokeyjail) == -1) die_pipe();
    keyjailchild = fork();
    switch (keyjailchild) {
        case -1:
            die_fork();
        case 0:
            alarm(0);
            close(fromkeyjail[0]);
            close(tokeyjail[1]);
            close(fromchild[0]);
            close(tochild[1]);
            close(0);
            if (dup(tokeyjail[0]) != 0) die_dup();
            close(1);
            if (dup(fromkeyjail[1]) != 1) die_dup();
            blocking_enable(0);
            blocking_enable(1);
            signal(SIGPIPE, SIG_IGN);
            signal(SIGCHLD, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            log_ip(0);
            tls_keyjail(&ctx);
            die(0);
    }
    close(fromkeyjail[1]);
    close(tokeyjail[0]);
    blocking_enable(fromkeyjail[0]);
    blocking_enable(tokeyjail[1]);
    tls_pipe_fromchild = fromkeyjail[0];
    tls_pipe_tochild = tokeyjail[1];
    tls_pipe_eng = &ctx.cc.eng;

    /* create selfpipe */
    if (pipe(selfpipe) == -1) die_pipe();

    /* handshake timeout */
    signal(SIGALRM, signalhandler);
    alarm(hstimeout);

    /* drop privileges, chroot, set limits, ... NETJAIL starts here */
    if (!ctx.flagnojail) {
        if (jail(ctx.jailaccount, ctx.jaildir, 1) == -1) die_jail();
    }

    if (ctx.anchorfn) {
        char *pubpem;
        size_t pubpemlen;
        /* get anchor PEM file, and parse it */
        fixpath(ctx.anchorfn);
        if (pipe_write(tls_pipe_tochild, ctx.anchorfn, strlen(ctx.anchorfn) + 1) == -1) die_writetopipe();
        pubpem = pipe_readalloc(tls_pipe_fromchild, &pubpemlen);
        if (!pubpem) die_readanchorpem(ctx.anchorfn);
        if (!tls_pubcrt_parse(&ctx.anchorcrt, pubpem, pubpemlen, ctx.anchorfn)) die_parseanchorpem(ctx.anchorfn);
        alloc_free(pubpem);
    }

    /* receive proxy-protocol string */
    if (ppin) {
        if (!ppin(0, localip, localport, remoteip, remoteport)) {
            die_ppin(ppinver);
        }
    }
    else {
        /* get connection info */
        (void) connectioninfo_get(localip, localport, remoteip, remoteport);
    }
    log_ip(iptostr(remoteipstr, remoteip));

    log_d1("start");

    /* TLS init */
    tls_profile(&ctx);

    /* main loop */
    for (;;) {
        unsigned int st;
        struct pollfd p[5];
        struct pollfd *q;
        struct pollfd *watch0;
        struct pollfd *watch1;
        struct pollfd *watchfromchild;
        struct pollfd *watchtochild;
        struct pollfd *watchfromselfpipe;
        unsigned char *buf;
        size_t len;

        st = br_ssl_engine_current_state(&ctx.cc.eng);
        if (st & BR_SSL_CLOSED) {
            int err;
            err = br_ssl_engine_last_error(&ctx.cc.eng);
            if (err == BR_ERR_OK) {
                if (handshakedone) {
                    log_i9("SSL closed normally: ", tls_version_str(br_ssl_engine_get_version(&ctx.cc.eng)), ", ",
                    tls_cipher_str(ctx.cc.eng.session.cipher_suite), ", ", tls_ecdhe_str(br_ssl_engine_get_ecdhe_curve(&ctx.cc.eng)),
                    ", sni='", br_ssl_engine_get_server_name(&ctx.cc.eng), "'");
                }
                else {
                    log_d1("SSL closed normally");
                }
            }
            else {
                if (err >= BR_ERR_SEND_FATAL_ALERT) {
                    err -= BR_ERR_SEND_FATAL_ALERT;
                    if (handshakedone) {
                        log_e2("SSL closed abnormally, sent alert: ", tls_error_str(err));
                    }
                    else {
                        log_d2("SSL closed abnormally, sent alert: ", tls_error_str(err));
                    }
                } else if (err >= BR_ERR_RECV_FATAL_ALERT) {
                    err -= BR_ERR_RECV_FATAL_ALERT;
                    if (handshakedone) {
                        log_e2("SSL closed abnormally, received alert: ", tls_error_str(err));
                    }
                    else {
                        log_d2("SSL closed abnormally, received alert: ", tls_error_str(err));
                    }
                }
                else {
                    if (handshakedone) {
                        log_e2("SSL closed abnormally: ", tls_error_str(err));
                    }
                    else {
                        log_d2("SSL closed abnormally: ", tls_error_str(err));
                    }
                }
            }
            break;
        }

        if ((st & BR_SSL_SENDAPP) && !handshakedone) {

            /* write connection info to the child */
            if (pipe_write(tochild[1], localip, sizeof localip) == -1) die_writetopipe();
            if (pipe_write(tochild[1], localport, sizeof localport) == -1) die_writetopipe();
            if (pipe_write(tochild[1], remoteip, sizeof remoteip) == -1) die_writetopipe();
            if (pipe_write(tochild[1], remoteport, sizeof remoteport) == -1) die_writetopipe();

            /* CN from anchor certificate */
            ctx.clientcrtbuf[sizeof ctx.clientcrtbuf - 1] = 0;
            if (userfromcert) {
                if (!ctx.clientcrt.status) die_extractcn(userfromcert);
                log_d4(userfromcert, " from the client certificate '", ctx.clientcrtbuf, "'");
                fixname(ctx.clientcrtbuf);
            }
            if (pipe_write(tochild[1], ctx.clientcrtbuf, strlen(ctx.clientcrtbuf) + 1) == -1) die_writetopipe();

            /* write proxy-protocol string */
            if (ppout) {
                char ppbuf[PROXYPROTOCOL_MAX];
                long long ppbuflen = 0;
                ppbuflen = ppout(ppbuf, sizeof ppbuf, localip, localport, remoteip, remoteport);
                if (ppbuflen <= 0) die_ppout(ppoutver);
                if (writeall(tochild[1], ppbuf, ppbuflen) == -1) die_writetopipe();
            }

            alarm(timeout);
            handshakedone = 1;

            log_d9("SSL connection: ", tls_version_str(br_ssl_engine_get_version(&ctx.cc.eng)), ", ",
            tls_cipher_str(ctx.cc.eng.session.cipher_suite), ", ", tls_ecdhe_str(br_ssl_engine_get_ecdhe_curve(&ctx.cc.eng)),
            ", sni='", br_ssl_engine_get_server_name(&ctx.cc.eng), "'");
        }

        watch0 = watch1 = watchfromchild = watchtochild = watchfromselfpipe = 0;
        q = p;

        if (st & BR_SSL_SENDREC) { watch1 = q; q->fd = 1; q->events = POLLOUT; ++q; }
        if (st & BR_SSL_RECVREC) { watch0 = q; q->fd = 0; q->events = POLLIN; ++q; }
        if (st & BR_SSL_RECVAPP) { watchtochild = q; q->fd = tochild[1]; q->events = POLLOUT; ++q; }
        if (st & BR_SSL_SENDAPP) { watchfromchild = q; q->fd = fromchild[0]; q->events = POLLIN; ++q; }
        watchfromselfpipe = q; q->fd = selfpipe[0]; q->events = POLLIN; ++q;

        if (jail_poll(p, q - p, -1) < 0) {
            watch0 = watch1 = watchfromchild = watchtochild = watchfromselfpipe =  0;
        }
        else {
            if (watch1) if (!watch1->revents) watch1 = 0;
            if (watch0) if (!watch0->revents) watch0 = 0;
            if (watchtochild) if (!watchtochild->revents) watchtochild = 0;
            if (watchfromchild) if (!watchfromchild->revents) watchfromchild = 0;
            if (watchfromselfpipe) if (!watchfromselfpipe->revents) watchfromselfpipe = 0;
        }

        /* recvapp */
        if (watchtochild) {
            buf = br_ssl_engine_recvapp_buf(&ctx.cc.eng, &len);
            r = write(tochild[1], buf, len);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) { log_d1("write to child failed"); break; }
            br_ssl_engine_recvapp_ack(&ctx.cc.eng, r);
            continue;
        }

        /* sendrec */
        if (watch1) {
            buf = br_ssl_engine_sendrec_buf(&ctx.cc.eng, &len);
            r = write(1, buf, len);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) { log_d1("write to standard output failed"); break; }
            br_ssl_engine_sendrec_ack(&ctx.cc.eng, r);
            continue;
        }

        /* recvrec */
        if (watch0) {
            buf = br_ssl_engine_recvrec_buf(&ctx.cc.eng, &len);
            r = read(0, buf, len);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                if (r < 0) log_d1("read from standard input failed");
                if (r == 0) log_t1("read from standard input failed, connection closed");
                break;
            }
            br_ssl_engine_recvrec_ack(&ctx.cc.eng, r);
            alarm(timeout); /* refresh timeout */
            continue;
        }

        /* sendapp */
        if (watchfromchild) {
            buf = br_ssl_engine_sendapp_buf(&ctx.cc.eng, &len);
            r = read(fromchild[0], buf, len);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                if (r < 0) log_d1("read from child failed");
                if (r == 0) log_t1("read from child failed, connection closed");
                br_ssl_engine_close(&ctx.cc.eng);
                br_ssl_engine_flush(&ctx.cc.eng, 0);
                continue;
            }
            br_ssl_engine_sendapp_ack(&ctx.cc.eng, r);
            br_ssl_engine_flush(&ctx.cc.eng, 0);
            alarm(timeout); /* refresh timeout */
            continue;
        }

        /* signal received */
        if (watchfromselfpipe) {
            log_d1("signal received");
            break;
        }
    }

    signal(SIGCHLD, SIG_DFL);
    signal(SIGALRM, SIG_DFL);

    /* wait for keyjail child */
    close(fromkeyjail[0]);
    close(tokeyjail[1]);
    do {
        r = waitpid(keyjail, &status, 0);
    } while (r == -1 && errno == EINTR);
    if (!WIFEXITED(status)) {
        log_t2("keyjail process killed by signal ", lognum(WTERMSIG(status)));
    }
    else {
        log_t2("keyjail exited with status ", lognum(WEXITSTATUS(status)));
    }

    /* wait for child */
    close(fromchild[0]);
    close(tochild[1]);
    do {
        r = waitpid(child, &status, 0);
    } while (r == -1 && errno == EINTR);
    errno = 0;
    if (!WIFEXITED(status)) {
        log_f2("child process killed by signal ", lognum(WTERMSIG(status)));
        die(111);
    }
    log_d2("child exited with status ", lognum(WEXITSTATUS(status)));
    die(WEXITSTATUS(status));
}

/* clang-format on */
