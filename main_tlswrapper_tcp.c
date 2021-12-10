#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include "randombytes.h"
#include "resolvehost.h"
#include "strtoport.h"
#include "socket.h"
#include "e.h"
#include "log.h"
#include "conn.h"
#include "tls.h"
#include "jail.h"
#include "randommod.h"
#include "main.h"

static struct context {
    const char *account;
    const char *empty_dir;
} ctx = {
    .account = 0,
    .empty_dir = "/var/lib/tlswraper/empty",
};

static unsigned char inbuf[4096];
static long long inbuflen = 0;
static int infinished = 0;
static unsigned char outbuf[4096];
static long long outbuflen = 0;
static int outfinished = 0;

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
static int fd = -1;

static int flagverbose = 1;

static void cleanup(void) {
    randombytes(ip, sizeof ip);
    randombytes(inbuf, sizeof inbuf);
    randombytes(outbuf, sizeof outbuf);
    randombytes(&ctx, sizeof ctx);
    {
        unsigned char stack[4096];
        randombytes(stack, sizeof stack);
    }
}

#define die(x) { cleanup(); _exit(x); }
#define die_jail() { log_f1("unable to create jail"); die(111); }
#define die_pipe() { log_f1("unable to create pipe"); die(111); }

static void usage(void) {
    log_u1("tlswrapper-tcp [options] host port");
    die(100);
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
    return ret;
}


static int selfpipe[2] = {-1, -1};

static void signalhandler(int signum) {
    (void) signum;
    write(selfpipe[1], "", 1);
}

int main_tlswrapper_tcp(int argc, char **argv) {

    char *x;
    long long i;

    signal(SIGPIPE, SIG_IGN);

    log_name("tlswrapper-tcp");

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
            /* timeouts */
            if (*x == 'T') {
                if (x[1]) { connecttimeoutstr =  x + 1; break; }
                if (argv[1]) { connecttimeoutstr = *++argv; break; }
            }
            if (*x == 't') {
                if (x[1]) { timeoutstr =  x + 1; break; }
                if (argv[1]) { timeoutstr = *++argv; break; }
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
    hoststr = *++argv;
    if (!hoststr) usage();
    portstr = *++argv;
    if (!strtoport(port, portstr)) {
        log_f3("unable to parse TCP port (a number 0 - 65535) from the string '", portstr, "'");
        die(100);
    }
    timeout = timeout_parse(timeoutstr);
    connecttimeout = timeout_parse(connecttimeoutstr);

    /* start */
    log_time(1);

    /* initialize randombytes */
    {
        char ch[1];
        randombytes(ch, sizeof ch);
    }

    /* resolve host */
    if (!resolvehost_init()) {
        log_f1("unable to create jailed process for DNS resolver");
        die(111);
    }
    iplen = resolvehost_do(ip, sizeof ip, hoststr);
    log_d2("iplen: ", lognum(iplen));
    if (iplen < 0) {
        log_f5("unable to resolve host '", hoststr, "' or port '", portstr, "'");
        die(111);
    }
    if (iplen == 0) {
        log_f3("unable to resolve host '", hoststr, "': name not exist");
        die(111);
    }
    for (i = 0; i < iplen; i += 16) {
        log_d3(hoststr, ": ", logip(ip + i));
    }

    /* create selfpipe */
    if (pipe(selfpipe) == -1) die_pipe();

    /* create sockets */
    if (conn_init(iplen / 16) == -1) {
        log_f1("unable to create TCP socket");
        die(111);
    }

    /* drop privileges, chroot, set limits, ... NETJAIL starts here */
    if (jail(ctx.account, ctx.empty_dir, 1) == -1) die_jail();

    fd = conn(connecttimeout, ip, iplen, port);
    if (fd == -1) {
        log_f4("unable to connect to ", hoststr, ":", logport(port));
        die(111);
    }

    log_d4("connected to [", logip(ip), "]:", logport(port));
    log_i4("connected to ", hoststr, ":", logport(port));

    signal(SIGTERM, signalhandler);
    signal(SIGALRM, signalhandler);
    alarm(timeout);

    for (;;) {
        long long r;
        struct pollfd p[5];
        struct pollfd *q;
        struct pollfd *watch0;
        struct pollfd *watch1;
        struct pollfd *watchfromremote;
        struct pollfd *watchtoremote;
        struct pollfd *watchfromselfpipe;

        if ((infinished || outfinished) && inbuflen == 0 && outbuflen == 0) break;

        watch0 = watch1 = watchfromremote = watchtoremote = watchfromselfpipe = 0;
        q = p;

        if (!infinished && sizeof inbuf > (unsigned long long) inbuflen) { watch0 = q; q->fd = 0; q->events = POLLIN; ++q; }
        if (outbuflen > 0) { watch1 = q; q->fd = 1; q->events = POLLOUT; ++q; }
        if (inbuflen > 0) { watchtoremote = q; q->fd = fd; q->events = POLLOUT; ++q; }
        if (!outfinished && sizeof outbuf > (unsigned long long) outbuflen) { watchfromremote = q; q->fd = fd; q->events = POLLIN; ++q; }
        watchfromselfpipe = q; q->fd = selfpipe[0]; q->events = POLLIN; ++q;

        if (jail_poll(p, q - p, -1) < 0) {
            watch0 = watch1 = watchfromremote = watchtoremote = watchfromselfpipe =  0;
        }
        else {
            if (watch1) if (!watch1->revents) watch1 = 0;
            if (watch0) if (!watch0->revents) watch0 = 0;
            if (watchtoremote) if (!watchtoremote->revents) watchtoremote = 0;
            if (watchfromremote) if (!watchfromremote->revents) watchfromremote = 0;
            if (watchfromselfpipe) if (!watchfromselfpipe->revents) watchfromselfpipe = 0;
        }

        if (watchtoremote) {
            r = write(fd, inbuf, inbuflen);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) { log_d5("write to ", hoststr, ":", portstr, " failed" ); break; }
            memmove(inbuf, inbuf + r, inbuflen - r);
            inbuflen -= r;
            continue;
        }

        if (watch1) {
            r = write(1, outbuf, outbuflen);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) { log_d1("write to standard output failed"); break; }
            memmove(outbuf, outbuf + r, outbuflen - r);
            outbuflen -= r;
            continue;
        }

        if (watch0) {
            r = read(0, inbuf + inbuflen, sizeof inbuf - inbuflen);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                if (r < 0) log_d1("read from standard input failed");
                if (r == 0) log_t1("read from standard input failed, connection closed");
                infinished = 1;
                continue;
            }
            inbuflen += r;
            alarm(timeout); /* refresh timeout */
            continue;
        }

        if (watchfromremote) {
            r = read(fd, outbuf + outbuflen, sizeof inbuf - outbuflen);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) { 
                if (r < 0) log_d5("read from ", hoststr, ":", portstr, " failed" ); 
                if (r == 0) log_t5("read from ", hoststr, ":", portstr, " failed, connection closed" );
                outfinished = 1;
                continue;
            }
            outbuflen += r;
            alarm(timeout); /* refresh timeout */
            continue;
        }

        /* signal received */
        if (watchfromselfpipe) {
            log_d1("signal received");
            break;
        }
    }

    log_d1("finished");
    die(0);
}
