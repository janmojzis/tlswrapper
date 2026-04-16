/*
 * main_tlswrapper_tcp.c - TCP forwarding front-end with optional PROXY headers
 *
 * Implements the TCP mode of tlswrapper. The process resolves a target host,
 * connects to the first reachable address, optionally consumes an incoming
 * PROXY protocol header from stdin, and can emit an outgoing PROXY protocol
 * header toward the remote side before entering a bidirectional forwarding
 * loop.
 */

#include <unistd.h>
#include <signal.h>
#include "randombytes.h"
#include "fd.h"
#include "iptostr.h"
#include "proxyprotocol.h"
#include "connectioninfo.h"
#include "resolvehost.h"
#include "strtoport.h"
#include "socket.h"
#include "e.h"
#include "log.h"
#include "conn.h"
#include "str.h"
#include "tls.h"
#include "jail.h"
#include "randommod.h"
#include "parsenum.h"
#include "alloc.h"
#include "main.h"

static struct context {
    const char *account;
    const char *empty_dir;
} ctx = {
    .account = 0,
    .empty_dir = EMPTYDIR,
};

static unsigned char inbuf[8192];
static unsigned long long inbuflen = 0;
static unsigned char outbuf[8192];
static unsigned long long outbuflen = 0;

#define NUMIP 8
static const char *timeoutstr = "3600";
static const char *connecttimeoutstr = "10";
static const char *hoststr = 0;
static const char *portstr = 0;

static long long timeout;
static long long connecttimeout;
static unsigned char ip[16 * NUMIP];
static long long iplen;
static unsigned char port[2];

static unsigned char localip[16] = {0};
static unsigned char localport[2] = {0};
static unsigned char remoteip[16] = {0};
static unsigned char remoteport[2] = {0};
static char remoteipstr[IPTOSTR_LEN] = {0};

static int flagverbose = 1;

/*
 * cleanup - overwrite connection state and transient buffers before exit
 *
 * Closes resolver helpers and randomizes sensitive runtime state so
 * connection metadata and buffered payloads do not remain in memory.
 */
static void cleanup(void) {
    resolvehost_close();
    randombytes(ip, sizeof ip);
    randombytes(port, sizeof port);
    randombytes(inbuf, sizeof inbuf);
    randombytes(outbuf, sizeof outbuf);
    randombytes(localip, sizeof localip);
    randombytes(localport, sizeof localport);
    randombytes(remoteip, sizeof remoteip);
    randombytes(remoteport, sizeof remoteport);
    randombytes(remoteipstr, sizeof remoteipstr);
    randombytes(&ctx, sizeof ctx);
    alloc_freeall();
    {
        unsigned char stack[4096];
        randombytes(stack, sizeof stack);
    }
}

#define die(x)                                                                 \
    do {                                                                       \
        cleanup();                                                             \
        _exit(x);                                                              \
    } while (0)
#define die_jail()                                                             \
    do {                                                                       \
        log_f1("unable to create jail");                                       \
        die(111);                                                              \
    } while (0)
#define die_pipe()                                                             \
    do {                                                                       \
        log_f1("unable to create pipe");                                       \
        die(111);                                                              \
    } while (0)
#define die_ppout(x)                                                           \
    do {                                                                       \
        log_f3("unable to create outgoing proxy-protocol v", (x), " string");  \
        die(100);                                                              \
    } while (0)
#define die_ppin(x)                                                            \
    do {                                                                       \
        log_f3("unable to receive incoming proxy-protocol v", (x), " string"); \
        die(100);                                                              \
    } while (0)
/*
 * usage - print command usage and exit
 */
static void __attribute__((noreturn)) usage(void) {
    log_u1("tlswrapper-tcp [options] host port");
    die(100);
}

/* proxy-protocol */
static long long (*ppout)(char *, long long, unsigned char *, unsigned char *,
                          unsigned char *, unsigned char *) = 0;
static const char *ppoutver = 0;
static int (*ppin)(int, unsigned char *, unsigned char *, unsigned char *,
                   unsigned char *) = 0;
static const char *ppinver = 0;

/*
 * pp_incoming - configure parsing of an incoming PROXY protocol header
 *
 * @x: textual protocol version selector
 */
static void pp_incoming(const char *x) {

    if (str_equal("0", x)) {
        /* disable incoming proxy-protocol */
        return;
    }
    else if (str_equal("1", x)) {
        ppin = proxyprotocol_v1_get;
        ppinver = x;
    }
    else {
        log_f3(
            "unable to parse incoming proxy-protocol version from the string '",
            x, "'");
        log_f1("available: 1");
        die(100);
    }
}
/*
 * pp_outgoing - configure emission of an outgoing PROXY protocol header
 *
 * @x: textual protocol version selector
 */
static void pp_outgoing(const char *x) {

    if (str_equal("0", x)) {
        /* disable outgoing proxy-protocol */
        return;
    }
    else if (str_equal("1", x)) {
        ppout = proxyprotocol_v1;
        ppoutver = x;
    }
    else {
        log_f3(
            "unable to parse outgoing proxy-protocol version from the string '",
            x, "'");
        log_f1("available: 1");
        die(100);
    }
}

/*
 * timeout_parse - parse and validate a timeout value in seconds
 *
 * @x: decimal timeout string
 *
 * Returns the parsed timeout. Invalid values terminate the process with a
 * usage error.
 */
static long long timeout_parse(const char *x) {
    long long ret;
    if (!parsenum(&ret, 1, 86400, x)) {
        log_f3("unable to parse timeout from the string '", x,
               "', timeout must be a number in the range <1,86400>");
        die(100);
    }
    return ret;
}

static int selfpipe[2] = {-1, -1};

/*
 * signalhandler - wake the forwarding loop on asynchronous signals
 *
 * @signum: delivered signal number
 *
 * SIGCHLD is ignored here; other watched signals write one byte to the
 * self-pipe so jail_poll() returns promptly.
 */
static void signalhandler(int signum) {
    int w;
    if (signum == SIGCHLD) return;
    w = write(selfpipe[1], "", 1);
    (void) w;
}

/*
 * main_tlswrapper_tcp - run the TCP forwarding front-end
 *
 * @argc: process argument count
 * @argv: process argument vector
 * @flagnojail: non-zero to skip privilege dropping and jailed helpers
 *
 * Parses command-line options, resolves the destination host, connects to the
 * remote side, optionally handles PROXY protocol headers, and then forwards
 * bytes between stdin/stdout and the remote socket until either side closes
 * or a signal interrupts the session.
 */
int main_tlswrapper_tcp(int argc, char **argv, int flagnojail) {

    char *x;
    long long i;
    int remotefds[2];
    int localinfd = 0;
    int localoutfd = 1;
    int remoteinfd = -1;
    int remoteoutfd = -1;

    errno = 0;
    signal(SIGPIPE, SIG_IGN);

    log_set_name("tlswrapper-tcp");
    log_set_id(0);

    /* clang-format off */
    (void) argc;
    if (!argv[0]) usage();
    for (;;) {
        if (!argv[1]) break;
        if (argv[1][0] != '-') break;
        x = *++argv;
        if (x[0] == '-' && x[1] == 0) break;
        if (x[0] == '-' && x[1] == '-' && x[2] == 0) break;
        while (*++x) {
            if (*x == 'q') { flagverbose = 0; log_set_level(flagverbose); continue; }
            if (*x == 'Q') { flagverbose = 1; log_set_level(flagverbose); continue; }
            if (*x == 'v') { log_set_level(++flagverbose); continue; }
            /* timeouts */
            if (*x == 'T') {
                if (x[1]) { connecttimeoutstr =  x + 1; break; }
                if (argv[1]) { connecttimeoutstr = *++argv; break; }
            }
            if (*x == 't') {
                if (x[1]) { timeoutstr =  x + 1; break; }
                if (argv[1]) { timeoutstr = *++argv; break; }
            }
            /* proxy-protocol */
            if (*x == 'p') {
                if (x[1]) { pp_incoming(x + 1); break; }
                if (argv[1]) { pp_incoming(*++argv); break; }
            }
            if (*x == 'P') {
                if (x[1]) { pp_outgoing(x + 1); break; }
                if (argv[1]) { pp_outgoing(*++argv); break; }
            }
            /* jail */
            if (*x == 'J') {
                if (x[1]) { ctx.empty_dir = (x + 1); break; }
                if (argv[1]) { ctx.empty_dir = (*++argv); break; }
            }
            if (*x == 'j') {
                if (x[1]) { ctx.account = (x + 1); break; }
                if (argv[1]) { ctx.account = (*++argv); break; }
            }
            usage();
        }
    }
    /* clang-format on */

    hoststr = *++argv;
    if (!hoststr) usage();
    portstr = *++argv;
    if (!strtoport(port, portstr)) {
        log_f3(
            "unable to parse TCP port (a number 0 - 65535) from the string '",
            portstr, "'");
        die(100);
    }
    timeout = timeout_parse(timeoutstr);
    connecttimeout = timeout_parse(connecttimeoutstr);

    /* Initialize randombytes before any cleanup path depends on it. */
    {
        char ch[1];
        randombytes(ch, sizeof ch);
    }

    /* Resolve all candidate addresses before entering the jail. */
    if (flagnojail) { iplen = resolvehost(ip, sizeof ip, hoststr); }
    else {
        if (!resolvehost_init()) {
            log_f1("unable to create jailed process for DNS resolver");
            die(111);
        }
        iplen = resolvehost_do(ip, sizeof ip, hoststr);
    }
    if (iplen < 0) {
        log_f5("unable to resolve host '", hoststr, "' or port '", portstr,
               "'");
        die(111);
    }
    if (iplen == 0) {
        log_f3("unable to resolve host '", hoststr, "': name not exist");
        die(111);
    }
    for (i = 0; i < iplen; i += 16) { log_d3(hoststr, ": ", log_ip(ip + i)); }
    resolvehost_close();

    /* Create the self-pipe used to interrupt the forwarding loop on signals. */
    if (pipe(selfpipe) == -1) die_pipe();

    /* Prepare one non-blocking socket per candidate address. */
    if (!conn_init(iplen / 16)) {
        log_f1("unable to create TCP socket");
        die(111);
    }

    /* NETJAIL starts here: drop privileges and install restrictive limits. */
    if (!flagnojail) {
        if (jail(ctx.account, ctx.empty_dir, 1) == -1) die_jail();
    }

    /* Load connection metadata from PROXY protocol or the inherited socket. */
    if (ppin) {
        if (!ppin(0, localip, localport, remoteip, remoteport)) {
            die_ppin(ppinver);
        }
    }
    else {
        /* get connection info */
        (void) connectioninfo_get(localip, localport, remoteip, remoteport);
    }
    log_set_ip(iptostr(remoteipstr, remoteip));
    log_t4("connection local=", log_ipport(localip, localport),
           " remote=", log_ipport(remoteip, remoteport));

    if (!conn(remotefds, connecttimeout, ip, iplen, port)) {
        log_f4("unable to connect to ", hoststr, ":", log_port(port));
        die(111);
    }
    remoteinfd = remotefds[0];
    remoteoutfd = remotefds[1];

    /* Prepend the outgoing PROXY header to the first bytes sent upstream. */
    if (ppout) {
        inbuflen = ppout((char *) inbuf, sizeof outbuf, localip, localport,
                         remoteip, remoteport);
        if (inbuflen <= 0) die_ppout(ppoutver);
        log_t4("prepared outgoing proxy-protocol header version=", ppoutver,
               ", len=", log_num(inbuflen));
    }

    log_d4("connected to [", log_ip(ip), "]:", log_port(port));
    log_i4("connected to ", hoststr, ":", log_port(port));

    signal(SIGTERM, signalhandler);
    signal(SIGALRM, signalhandler);
    alarm(timeout);
    log_t1("tcp forwarding loop entered");

    for (;;) {
        long long r;
        struct pollfd p[5];
        struct pollfd *q;
        struct pollfd *watch0;
        struct pollfd *watch1;
        struct pollfd *watchfromremote;
        struct pollfd *watchtoremote;
        struct pollfd *watchfromselfpipe;

        if (localinfd == -1 && remoteoutfd != -1 && inbuflen == 0) {
            fd_close_write("remoteoutfd", &remoteoutfd);
            log_t1("stdin closed, propagated EOF to remote");
        }
        if (remoteinfd == -1 && localoutfd != -1 && outbuflen == 0) {
            fd_close_write("localoutfd", &localoutfd);
            log_t1("remote closed, propagated EOF to stdout");
        }
        if (localinfd == -1 && remoteinfd == -1 && remoteoutfd == -1 &&
            localoutfd == -1 && inbuflen == 0 && outbuflen == 0) {
            log_t1("tcp forwarding loop finished");
            break;
        }

        watch0 = watch1 = watchfromremote = watchtoremote = watchfromselfpipe =
            0;
        q = p;

        if (localinfd != -1 && remoteoutfd != -1 && sizeof inbuf > inbuflen) {
            watch0 = q;
            q->fd = localinfd;
            q->events = POLLIN;
            ++q;
        }
        if (localoutfd != -1 && outbuflen > 0) {
            watch1 = q;
            q->fd = localoutfd;
            q->events = POLLOUT;
            ++q;
        }
        if (remoteoutfd != -1 && (inbuflen > 0 || localinfd == -1)) {
            watchtoremote = q;
            q->fd = remoteoutfd;
            q->events = POLLOUT;
            ++q;
        }
        if (remoteinfd != -1 && localoutfd != -1 && sizeof outbuf > outbuflen) {
            watchfromremote = q;
            q->fd = remoteinfd;
            q->events = POLLIN;
            ++q;
        }
        watchfromselfpipe = q;
        q->fd = selfpipe[0];
        q->events = POLLIN;
        ++q;

        if (jail_poll(p, q - p, -1) < 0) {
            watch0 = watch1 = watchfromremote = watchtoremote =
                watchfromselfpipe = 0;
        }
        else {
            if (watch1)
                if (!watch1->revents) watch1 = 0;
            if (watch0)
                if (!watch0->revents) watch0 = 0;
            if (watchtoremote)
                if (!watchtoremote->revents) watchtoremote = 0;
            if (watchfromremote)
                if (!watchfromremote->revents) watchfromremote = 0;
            if (watchfromselfpipe)
                if (!watchfromselfpipe->revents) watchfromselfpipe = 0;
        }

        if (watchtoremote) {
            if (inbuflen > 0) {
                r = fd_write("remoteoutfd", remoteoutfd, inbuf, inbuflen);
                if (r == -1)
                    if (errno == EINTR || errno == EAGAIN) continue;
                if (r <= 0) {
                    fd_close_write("remoteoutfd", &remoteoutfd);
                    break;
                }
                memmove(inbuf, inbuf + r, inbuflen - r);
                inbuflen -= r;
            }
            continue;
        }

        if (watch1) {
            r = fd_write("localoutfd", localoutfd, outbuf, outbuflen);
            if (r == -1)
                if (errno == EINTR || errno == EAGAIN) continue;
            if (r <= 0) {
                fd_close_write("localoutfd", &localoutfd);
                break;
            }
            memmove(outbuf, outbuf + r, outbuflen - r);
            outbuflen -= r;
            continue;
        }

        if (watch0) {
            r = fd_read("localinfd", localinfd, inbuf + inbuflen,
                        sizeof inbuf - inbuflen);
            if (r == -1)
                if (errno == EINTR || errno == EAGAIN) continue;
            if (r <= 0) {
                fd_close_read("localinfd", &localinfd);
                continue;
            }
            inbuflen += r;
            alarm(timeout); /* refresh timeout */
            continue;
        }

        if (watchfromremote) {
            r = fd_read("remoteinfd", remoteinfd, outbuf + outbuflen,
                        sizeof outbuf - outbuflen);
            if (r == -1)
                if (errno == EINTR || errno == EAGAIN) continue;
            if (r <= 0) {
                fd_close_read("remoteinfd", &remoteinfd);
                continue;
            }
            outbuflen += r;
            alarm(timeout); /* refresh timeout */
            continue;
        }

        /* Stop forwarding after a watched signal wakes the self-pipe. */
        if (watchfromselfpipe) {
            log_d1("signal received, tcp forwarding interrupted");
            break;
        }
    }

    fd_close_read("remoteinfd", &remoteinfd);
    fd_close_write("remoteoutfd", &remoteoutfd);
    log_d1("finished");
    die(0);
}
