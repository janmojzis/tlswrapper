/*
 * main_tlswrapper.c - main entry point for the tlswrapper multicall binary
 *
 * This module implements the primary tlswrapper program mode. It parses
 * command-line options, prepares the TLS context, starts the wrapped
 * child program and helper processes.
 */

#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include "blocking.h"
#include "pipe.h"
#include "log.h"
#include "e.h"
#include "jail.h"
#include "parsenum.h"
#include "randombytes.h"
#include "alloc.h"
#include "connectioninfo.h"
#include "proxyprotocol.h"
#include "iptostr.h"
#include "writeall.h"
#include "fixname.h"
#include "fixpath.h"
#include "socket.h"
#include "str.h"
#include "tls.h"
#include "open.h"
#include "main.h"

/* clang-format off */

static struct tls_context ctx = {
    .flags = (tls_flags_ENFORCE_SERVER_PREFERENCES | tls_flags_NO_RENEGOTIATION),
    .flaghandshakedone = 0,
    .flagdelayedenc = 0,
    .flagnojail = 0,
    .jailaccount = 0,
    .jaildir = EMPTYDIR,
    .version_min = tls_version_TLS12,
    .version_max = tls_version_TLS12,
    .ecdhe_enabled = ((uint32_t) 1 << tls_ecdhe_X25519) | ((uint32_t) 1 << tls_ecdhe_SECP256R1),
    .cipher_enabled_len = 0,
    .certfiles_len = 0,
    .anchorfn = 0,
    .clientcrtbuf = {0},
    .clientcrt.oid = 0,
};

#define CONTROLPIPEFD 5

static const char *hstimeoutstr = "30";
static const char *timeoutstr = "60";
static const char *user = 0;
static const char *userfromcert = 0;

static long long starttimeout = 3;
static long long hstimeout;
static long long timeout;

static int flagverbose = 1;

static int fromchildcontrol[2] = {-1, -1};
static int fromchild[2] = {-1, -1};
static int tochild[2] = {-1, -1};
static pid_t child = -1;
static int status;

static int fromkeyjail[2] = {-1, -1};
static int tokeyjail[2] = {-1, -1};
static pid_t keyjailchild = -1;

static int selfpipe[2] = {-1, -1};
static int netinfd = -1;
static int netoutfd = -1;
static int childoutfd = -1;
static int childinfd = -1;
static int controlfd = -1;

#define CLEARTEXT_BUFSIZE 8192
static unsigned char cleartext_tochildbuf[CLEARTEXT_BUFSIZE];
static size_t cleartext_tochildbuflen = 0;
static unsigned char cleartext_tonetbuf[CLEARTEXT_BUFSIZE];
static size_t cleartext_tonetbuflen = 0;
static unsigned char cleartext_tonet5buf[CLEARTEXT_BUFSIZE];
static size_t cleartext_tonet5buflen = 0;

static unsigned char localip[16] = {0};
static unsigned char localport[2] = {0};
static unsigned char remoteip[16] = {0};
static unsigned char remoteport[2] = {0};
static char remoteipstr[IPTOSTR_LEN] = {0};

/*
 * signalhandler - convert asynchronous signals into loop wakeups
 *
 * @signum: delivered signal number
 *
 * SIGCHLD shortens the active alarm so the main loop notices child exit
 * promptly. Other watched signals write one byte to the self-pipe so the
 * poll loop can handle shutdown in process context.
 */
static void signalhandler(int signum) {
    int w;
    if (signum == SIGCHLD) {
        alarm(1);
        return;
    }
    w = write(selfpipe[1], "", 1);
    (void) w;
}

/*
 * cleanup - wipe transient state before exiting the process
 *
 * Randomizes in-memory connection state and temporary stack storage, then
 * releases heap allocations tracked by the local allocator.
 *
 * Security:
 *   - overwrites process-local buffers before _exit()
 */
static void cleanup(void) {
    randombytes(&ctx, sizeof ctx);
    randombytes(localip, sizeof localip);
    randombytes(localport, sizeof localport);
    randombytes(remoteip, sizeof remoteip);
    randombytes(remoteport, sizeof remoteport);
    randombytes(remoteipstr, sizeof remoteipstr);
    randombytes(cleartext_tochildbuf, sizeof cleartext_tochildbuf);
    randombytes(&cleartext_tochildbuflen, sizeof cleartext_tochildbuflen);
    randombytes(cleartext_tonetbuf, sizeof cleartext_tonetbuf);
    randombytes(&cleartext_tonetbuflen, sizeof cleartext_tonetbuflen);
    randombytes(cleartext_tonet5buf, sizeof cleartext_tonet5buf);
    randombytes(&cleartext_tonet5buflen, sizeof cleartext_tonet5buflen);
    alloc_freeall();
    {
        unsigned char stack[4096];
        randombytes(stack, sizeof stack);
    }
}

#define die(x) { cleanup(); _exit(x); }
#define die_pipe() { log_f1("unable to create pipe"); die(111); }
#define die_controlpipe() { log_f3("unable to create control pipe on filedescriptor ", log_num(CONTROLPIPEFD), ": filedescriptor exits"); die(111); }
#define die_devnull() { log_f1("unable to open /dev/null"); die(111); }
#define die_writetopipe() { log_f1("unable to write to pipe"); die(111); }
#define die_fork() { log_f1("unable to fork"); die(111); }
#define die_dup() { log_f1("unable to dup"); die(111); }
#define die_droppriv(x) { log_f3("unable to drop privileges to '", (x), "'"); die(111); }
#define die_jail() { log_f1("unable to create jail"); die(111); }
#define die_readanchorpem(x) { log_f3("unable to read anchor PEM file '", (x), "'"); die(111); }
#define die_parseanchorpem(x) { log_f3("unable to parse anchor PEM file '", (x), "'"); die(111); }
#define die_extractcn(x) { log_f3("unable to extract ASN.1 object ", (x), " from client certificate: object not found"); die(111); }
#define die_optionUa() { log_f1("option -U must be used with -a"); die(100); }
#define die_optionUn() { log_f1("option -U is not compatible with -n"); die(100); }
#define die_ppin(x) { log_f3("unable to receive incoming proxy-protocol v", (x), " string");; die(100); }


/* proxy-protocol */
static int (*ppin)(int, unsigned char *, unsigned char *, unsigned char *, unsigned char *) = 0;
static const char *ppinver = 0;

/*
 * pp_incoming - configure incoming proxy-protocol parsing
 *
 * @x: requested proxy-protocol version string
 *
 * Enables parsing of a supported incoming proxy-protocol header or
 * disables it when "0" is selected.
 */
static void pp_incoming(const char *x) {

    if (str_equal("0", x)) {
        /* disable incoming proxy-protocol*/
        return;
    }
    else if (str_equal("1", x)) {
        ppin = proxyprotocol_v1_get;
        ppinver = x;
    }
    else {
        log_f3("unable to parse incoming proxy-protocol version from the string '", x, "'");
        log_f1("available: 1");
        die(100);
    }
}

/*
 * certuser_add - select the client-certificate field used as login name
 *
 * @x: ASN.1 field name from the command line
 *
 * Maps a supported field name to the certificate OID extracted after
 * client authentication succeeds.
 */
static void certuser_add(const char *x) {

    userfromcert = x;
    if (str_equal("commonName", x)) {
        ctx.clientcrt.oid = (unsigned char *)"\003\125\004\003";
    }
    else if (str_equal("emailAddress", x)) {
        ctx.clientcrt.oid = (unsigned char *)"\011\052\206\110\206\367\015\001\011\001";
    }
    else {
        log_f3("unable to parse ASN.1 object from the string '", x, "'");
        log_f1("available: commonName");
        log_f1("available: emailAddress");
        die(100);
    }
}

/*
 * version_setmax - parse and store the highest allowed TLS version
 *
 * @x: version name from the command line
 *
 * Exits with usage failure when the supplied version name is unsupported.
 */
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

/*
 * version_setmin - parse and store the lowest allowed TLS version
 *
 * @x: version name from the command line
 *
 * Exits with usage failure when the supplied version name is unsupported.
 */
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

/*
 * certfile_add_dir - register a certificate directory for SNI lookup
 *
 * @x: directory path
 *
 * Verifies that the path is a directory and stores it in the TLS context.
 */
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
        log_f3("unable to add more than ", log_num(tls_CERTFILES), " certdirs+certfiles");
        die(100);
    }
}

/*
 * certfile_add_file - register a fixed certificate PEM file
 *
 * @x: PEM file path
 *
 * Verifies that the path is a regular file and stores it in the TLS
 * context for later certificate selection.
 */
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
        log_f3("unable to add more than ", log_num(tls_CERTFILES), " certdirs+certfiles");
        die(100);
    }
}

/*
 * anchor_add - register the client-certificate trust anchor
 *
 * @x: anchor PEM file path
 *
 * Accepts exactly one regular file that will later be parsed and used for
 * client-certificate verification.
 */
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

/*
 * ecdhe_add - enable one supported key-exchange curve
 *
 * @x: curve name from the command line
 *
 * Extends the enabled curve set or exits with usage failure for an
 * unknown name.
 */
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

/*
 * cipher_add - enable one supported TLS cipher suite
 *
 * @x: cipher name from the command line
 *
 * Extends the enabled cipher list or exits with usage failure for an
 * unknown name.
 */
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

/*
 * timeout_parse - parse and validate a timeout value in seconds
 *
 * @x: decimal timeout string
 *
 * Returns the parsed timeout after enforcing the accepted range.
 */
static long long timeout_parse(const char *x) {
    long long ret;
    if (!parsenum(&ret, 1, 86400, x)) {
        log_f3("unable to parse timeout from the string '", x, "', timeout must be a number in the range <1,86400>");
        die(100);
    }
    return ret;
}

/*
 * consume_buffer - drop bytes from the front of a pending buffer
 *
 * @buf: buffer storage
 * @buflen: current number of valid bytes
 * @len: number of bytes already consumed
 */
static void consume_buffer(unsigned char *buf, size_t *buflen, size_t len) {
    if (!len) return;
    memmove(buf, buf + len, *buflen - len);
    *buflen -= len;
}

/*
 * close_rfd - close a tracked read descriptor and mark it inactive
 *
 * @fd: descriptor slot to close
 */
static void close_rfd(int *fd) {
    if (*fd != -1) {
        close(*fd);
        *fd = -1;
    }
}

/*
 * close_wfd - close a tracked write descriptor and mark it inactive
 *
 * @fd: descriptor slot to close
 *
 * Uses shutdown(SHUT_WR) for socket-backed transports and falls back to a
 * plain close when the descriptor is not a socket.
 */
static int close_wfd(int *fd) {
    if (*fd == -1) return 1;
    if (socket_shutdown(*fd) == -1) {
        if (errno != ENOTCONN && errno != EBADF &&
            errno != ENOTSOCK && errno != EINVAL) return 0;
    }
    close_rfd(fd);
    return 1;
}

/*
 * report_tls_user - send the one-shot login/account record to the child
 *
 * @userstr: NUL-terminated value to forward
 * @flaguserreported: tracks whether the record was already delivered
 */
static void report_tls_user(const char *userstr, int *flaguserreported) {
    if (pipe_write(childinfd, userstr, str_len(userstr) + 1) == -1) {
        die_writetopipe();
    }
    *flaguserreported = 1;
}

/*
 * report_tls_handshake - publish post-handshake metadata once
 *
 * @st: current TLS engine state flags
 * @flaguserreported: tracks whether the child already received the login string
 */
static void report_tls_handshake(unsigned int st, int *flaguserreported) {

    if (ctx.flaghandshakedone) return;
    if (!(st & tls_state_SENDAPP)) return;
    ctx.flaghandshakedone = 1;

    /* CN from anchor certificate */
    if (!*flaguserreported) {
        ctx.clientcrtbuf[sizeof ctx.clientcrtbuf - 1] = 0;
        if (userfromcert) {
            if (!ctx.clientcrt.status) die_extractcn(userfromcert);
            log_d4(userfromcert, " from the client certificate '",
                   ctx.clientcrtbuf, "'");
            fixname(ctx.clientcrtbuf);
        }
        report_tls_user((char *)ctx.clientcrtbuf, flaguserreported);
    }

    log_i9("SSL connection: ", tls_version_str(tls_engine_get_version(&ctx)),
           ", ", tls_cipher_str(tls_engine_get_cipher(&ctx)), ", ",
           tls_ecdhe_str(tls_engine_get_ecdhe_curve(&ctx)),
           ", sni='", tls_engine_get_server_name(&ctx), "'");

    alarm(timeout);
}

/*
 * run_cleartext_phase - forward plaintext until the child requests STARTTLS
 *
 * Returns 1 when the delayed-encryption control pipe requests STARTTLS and
 * 0 when the session should terminate without entering TLS.
 */
static int run_cleartext_phase(void) {
    cleartext_tochildbuflen = 0;
    cleartext_tonetbuflen = 0;
    cleartext_tonet5buflen = 0;
    log_t1("cleartext phase entered");

    for (;;) {
        struct pollfd p[6];
        struct pollfd *q;
        struct pollfd *watchfromnet;
        struct pollfd *watchtonet;
        struct pollfd *watchfromchild;
        struct pollfd *watchtochild;
        struct pollfd *watchfromselfpipe;
        struct pollfd *watchfromcontrol;
        long long r;

        /* EOF propagation: once one side is gone and its buffer has been
           flushed, half-close the opposite direction so the peer sees EOF. */
        if (netinfd == -1 && childinfd != -1 && !cleartext_tochildbuflen) {
            if (!close_wfd(&childinfd)) {
                log_d1("write side close to child failed");
                return 0;
            }
            log_t1("network peer closed the connection, cleartext phase propagated network EOF to child");
        }
        if (childoutfd == -1 && netoutfd != -1 && !cleartext_tonetbuflen) {
            if (!close_wfd(&netoutfd)) {
                log_d1("write side close to remote failed");
                return 0;
            }
            log_d1("child closed the connection, cleartext phase propagated child EOF to network");
        }

        /* Termination: all four descriptors closed, nothing left to relay. */
        if (netinfd == -1 && childinfd == -1 && childoutfd == -1 && netoutfd == -1) {
            log_t1("cleartext phase finished");
            return 0;
        }

        /* STARTTLS guards: abort when the transition cannot succeed.
           - network half-closed: TLS handshake is impossible.
           - control buffer full: cannot read EOF, transition will never
             complete; the child wrote garbage to the control pipe. */
        if (cleartext_tonet5buflen) {
            if (netinfd == -1 || netoutfd == -1) {
                log_d1("STARTTLS pending but network descriptors already closed, aborting");
                return 0;
            }
            if (cleartext_tonet5buflen >= sizeof cleartext_tonet5buf) {
                log_d1("STARTTLS control buffer full, aborting");
                return 0;
            }
        }

        watchfromnet = watchtonet = watchfromchild = watchtochild = watchfromselfpipe = 0;
        watchfromcontrol = 0;
        q = p;

        /* Flush: always allow draining pending data to its destination. */
        if (netoutfd != -1 && cleartext_tonetbuflen) {
            watchtonet = q;
            q->fd = netoutfd;
            q->events = POLLOUT;
            ++q;
        }
        if (cleartext_tochildbuflen && childinfd != -1) {
            watchtochild = q;
            q->fd = childinfd;
            q->events = POLLOUT;
            ++q;
        }

        /* Ingest: accept new cleartext data only when no STARTTLS signal
           has arrived yet.  Once cleartext_tonet5buflen > 0 the child has
           declared its intent to switch to TLS; accepting more cleartext
           would let the child interleave data across the TLS boundary. */
        if (!cleartext_tonet5buflen &&
            netinfd != -1 &&
            cleartext_tochildbuflen < sizeof cleartext_tochildbuf &&
            childinfd != -1) {
            watchfromnet = q;
            q->fd = netinfd;
            q->events = POLLIN;
            ++q;
        }
        if (!cleartext_tonet5buflen &&
            childoutfd != -1 && cleartext_tonetbuflen < sizeof cleartext_tonetbuf) {
            watchfromchild = q;
            q->fd = childoutfd;
            q->events = POLLIN;
            ++q;
        }

        /* Control pipe: read the STARTTLS signal only after both cleartext
           buffers have been flushed, so the transition point is clean. */
        if (childoutfd != -1 && netoutfd != -1 &&
            controlfd != -1 &&
            cleartext_tonet5buflen < sizeof cleartext_tonet5buf &&
            !cleartext_tonetbuflen && !cleartext_tochildbuflen) {
            watchfromcontrol = q;
            q->fd = controlfd;
            q->events = POLLIN;
            ++q;
        }

        /* Signal pipe: always monitored for SIGCHLD / SIGTERM. */
        watchfromselfpipe = q;
        q->fd = selfpipe[0];
        q->events = POLLIN;
        ++q;

        if (jail_poll(p, q - p, -1) < 0) {
            watchfromnet = watchtonet = watchfromchild = watchtochild = watchfromselfpipe = 0;
            watchfromcontrol = 0;
        }
        else {
            if (watchtonet) if (!watchtonet->revents) watchtonet = 0;
            if (watchtochild) if (!watchtochild->revents) watchtochild = 0;
            if (watchfromnet) if (!watchfromnet->revents) watchfromnet = 0;
            if (watchfromchild) if (!watchfromchild->revents) watchfromchild = 0;
            if (watchfromcontrol) if (!watchfromcontrol->revents) watchfromcontrol = 0;
            if (watchfromselfpipe) if (!watchfromselfpipe->revents) watchfromselfpipe = 0;
        }

        /* --- event handlers, highest-to-lowest priority ---
           Writes are handled before reads so that buffer space is freed
           before new data arrives.  The control pipe is read last to
           guarantee cleartext buffers are drained first. */

        /* Flush: network->child */
        if (watchtochild) {
            r = write(childinfd, cleartext_tochildbuf, cleartext_tochildbuflen);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                (void)close_wfd(&childinfd);
                log_d1("write to child failed");
                return 0;
            }
            log_t4("write(childinfd, cleartext_tochildbuf, len=",
                   log_num(cleartext_tochildbuflen), ") = ", log_num(r));
            consume_buffer(cleartext_tochildbuf, &cleartext_tochildbuflen, (size_t) r);
            continue;
        }

        /* Flush: child->network */
        if (watchtonet) {
            r = write(netoutfd, cleartext_tonetbuf, cleartext_tonetbuflen);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                (void)close_wfd(&netoutfd);
                log_d1("write to standard output failed");
                return 0;
            }
            log_t4("write(netoutfd, cleartext_tonetbuf, len=", log_num(cleartext_tonetbuflen),
                   ") = ", log_num(r));
            consume_buffer(cleartext_tonetbuf, &cleartext_tonetbuflen, (size_t) r);
            continue;
        }

        /* Ingest: network->child (disabled after STARTTLS signal) */
        if (watchfromnet) {
            r = read(netinfd, cleartext_tochildbuf + cleartext_tochildbuflen,
                     sizeof cleartext_tochildbuf - cleartext_tochildbuflen);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                if (r < 0) log_d1("read from standard input failed");
                if (r == 0) log_t1("read from standard input failed, connection closed");
                close_rfd(&netinfd);
                continue;
            }
            log_t4("read(netinfd, cleartext_tochildbuf + len, free=",
                   log_num(sizeof cleartext_tochildbuf - cleartext_tochildbuflen),
                   ") = ", log_num(r));
            cleartext_tochildbuflen += (size_t) r;
            alarm(timeout);
            continue;
        }

        /* Ingest: child->network (disabled after STARTTLS signal) */
        if (watchfromchild) {
            r = read(childoutfd, cleartext_tonetbuf + cleartext_tonetbuflen,
                     sizeof cleartext_tonetbuf - cleartext_tonetbuflen);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                if (r < 0) log_d1("read from child failed");
                if (r == 0) log_t1("read from child failed, connection closed");
                close_rfd(&childoutfd);
                continue;
            }
            log_t4("read(childoutfd, cleartext_tonetbuf + len, free=",
                   log_num(sizeof cleartext_tonetbuf - cleartext_tonetbuflen),
                   ") = ", log_num(r));
            cleartext_tonetbuflen += (size_t) r;
            alarm(timeout);
            continue;
        }

        /* Control pipe: STARTTLS signalling from the child.
           - Partial read (r > 0): accumulate the banner; on the next
             iteration the ingest guards will block new cleartext.
           - EOF (r == 0): child closed fd 5 — drain any residual
             cleartext buffers, flush the STARTTLS banner to the
             network, and return 1 to enter the TLS phase.
           - Empty EOF: control pipe closed without data — the child
             decided not to request STARTTLS; end the cleartext phase. */
        if (watchfromcontrol) {
            r = read(controlfd, cleartext_tonet5buf + cleartext_tonet5buflen,
                     sizeof cleartext_tonet5buf - cleartext_tonet5buflen);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r == -1) {
                close_rfd(&controlfd);
                log_d1("read from child failed");
                return 0;
            }
            if (r == 0) {
                close_rfd(&controlfd);
                if (!cleartext_tonet5buflen) {
                    log_d1("control pipe closed before STARTTLS, cleartext phase ended");
                    return 0;
                }
                if (cleartext_tonetbuflen) {
                    if (writeall(netoutfd, cleartext_tonetbuf, cleartext_tonetbuflen) == -1) {
                        log_d1("write to standard output failed (pending child data)");
                        return 0;
                    }
                    log_t2("drained pending cleartext_tonetbuf bytes ",
                           log_num(cleartext_tonetbuflen));
                    cleartext_tonetbuflen = 0;
                }
                if (cleartext_tochildbuflen) {
                    if (writeall(childinfd, cleartext_tochildbuf, cleartext_tochildbuflen) == -1) {
                        log_d1("write to child failed (pending net data)");
                        return 0;
                    }
                    log_t2("drained pending cleartext_tochildbuf bytes ",
                           log_num(cleartext_tochildbuflen));
                    cleartext_tochildbuflen = 0;
                }
                if (writeall(netoutfd, cleartext_tonet5buf, cleartext_tonet5buflen) == -1) {
                    log_d1("write to standard output failed");
                    return 0;
                }
                log_d2("child requested encryption(STARTTLS), flushed bytes ",
                       log_num(cleartext_tonet5buflen));
                return 1;
            }
            cleartext_tonet5buflen += (size_t) r;
            continue;
        }

        /* Signal pipe: child died or timeout fired. */
        if (watchfromselfpipe) {
            log_d1("signal received, cleartext phase interrupted");
            return 0;
        }
    }
}

/*
 * run_tls_phase - forward bytes between the TLS engine, the network, and the child
 *
 * @flaguserreported: tracks whether the child already received the login string
 */
static void run_tls_phase(int *flaguserreported) {
    log_t1("tls phase entered");
    for (;;) {
        unsigned int st;
        struct pollfd p[5];
        struct pollfd *q;
        struct pollfd *watchfromnet;
        struct pollfd *watchtonet;
        struct pollfd *watchfromchild;
        struct pollfd *watchtochild;
        struct pollfd *watchfromselfpipe;
        unsigned char *buf;
        size_t len;
        long long r;

        st = tls_engine_current_state(&ctx);
        report_tls_handshake(st, flaguserreported);


        /* Handshake failed — tear down immediately, nothing useful
         * can happen on this connection any more.
         */
        if ((st & tls_state_CLOSED) && !ctx.flaghandshakedone) {
            log_d1("handshake failed, tls phase ended during handshake");
            break;
        }

        /* TLS engine is done and all pending records have been flushed —
         * nothing useful remains on this connection.
         */
        if ((st & tls_state_CLOSED) && !(st & tls_state_SENDREC)) {
            log_t1("tls phase finished after engine close");
            break;
        }

        /* Unclean TCP close without close_notify: the peer has closed
         * the connection and the engine has no more plaintext pending
         * for the child, so propagate EOF to the wrapped program.
         */
        if (netinfd == -1 && childinfd != -1 && !(st & tls_state_RECVAPP)) {
            if (!close_wfd(&childinfd)) {
                log_d1("write side close to child failed");
                break;
            }
            log_t1("tls phase propagated peer EOF to child");
        }


        watchfromnet = watchtonet = watchfromchild = watchtochild = watchfromselfpipe = 0;
        q = p;

        if (netoutfd != -1 && (st & tls_state_SENDREC)) {
            watchtonet = q;
            q->fd = netoutfd;
            q->events = POLLOUT;
            ++q;
        }
        if (netinfd != -1 && (st & tls_state_RECVREC)) {
            watchfromnet = q;
            q->fd = netinfd;
            q->events = POLLIN;
            ++q;
        }
        if (childinfd != -1 && (st & tls_state_RECVAPP)) {
            watchtochild = q;
            q->fd = childinfd;
            q->events = POLLOUT;
            ++q;
        }
        if (childoutfd != -1 && (st & tls_state_SENDAPP)) {
            watchfromchild = q;
            q->fd = childoutfd;
            q->events = POLLIN;
            ++q;
        }
        watchfromselfpipe = q; q->fd = selfpipe[0]; q->events = POLLIN; ++q;

        if (jail_poll(p, q - p, -1) < 0) {
            watchfromnet = watchtonet = watchfromchild = watchtochild = watchfromselfpipe = 0;
        }
        else {
            if (watchtonet) if (!watchtonet->revents) watchtonet = 0;
            if (watchfromnet) if (!watchfromnet->revents) watchfromnet = 0;
            if (watchtochild) if (!watchtochild->revents) watchtochild = 0;
            if (watchfromchild) if (!watchfromchild->revents) watchfromchild = 0;
            if (watchfromselfpipe) if (!watchfromselfpipe->revents) watchfromselfpipe = 0;
        }

        if (watchtochild) {
            buf = tls_engine_recvapp_buf(&ctx, &len);
            r = write(childinfd, buf, len);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                (void)close_wfd(&childinfd);
                log_d1("write to child failed");
                break;
            }
            log_t4("write(childinfd, buf, len=", log_num(len), ") = ", log_num(r));
            tls_engine_recvapp_ack(&ctx, r);
            continue;
        }

        if (watchtonet) {
            buf = tls_engine_sendrec_buf(&ctx, &len);
            r = write(netoutfd, buf, len);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                (void)close_wfd(&netoutfd);
                log_d1("write to standard output failed");
                break;
            }
            log_t4("write(netoutfd, buf, len=", log_num(len), ") = ", log_num(r));
            tls_engine_sendrec_ack(&ctx, r);
            continue;
        }

        if (watchfromnet) {
            buf = tls_engine_recvrec_buf(&ctx, &len);
            r = read(netinfd, buf, len);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                if (r < 0) log_d1("read from standard input failed");
                if (r == 0) log_t1("read from standard input failed, connection closed");
                close_rfd(&netinfd);
                continue;
            }
            log_t4("read(netinfd, buf, len=", log_num(len), ") = ", log_num(r));
            tls_engine_recvrec_ack(&ctx, r);
            alarm(timeout);
            continue;
        }

        if (watchfromchild) {
            buf = tls_engine_sendapp_buf(&ctx, &len);
            r = read(childoutfd, buf, len);
            if (r == -1) if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (r <= 0) {
                if (r < 0) log_d1("read from child failed");
                if (r == 0) log_t1("read from child failed, connection closed");
                close_rfd(&childoutfd);
                tls_engine_close(&ctx);
                tls_engine_flush(&ctx, 0);
                continue;
            }
            log_t4("read(childoutfd, buf, len=", log_num(len), ") = ", log_num(r));
            tls_engine_sendapp_ack(&ctx, r);
            tls_engine_flush(&ctx, 0);
            alarm(timeout);
            continue;
        }

        if (watchfromselfpipe) {
            log_d1("signal received, tls phase interrupted");
            break;
        }
    }
}

/*
 * usage - print short command usage and terminate
 */
static void usage(void) {
    log_u1("tlswrapper [options] [ -d certdir ] [ -f certfile ] prog");
    die(100);
}

/*
 * main_tlswrapper - start the wrapper and bridge one TLS session
 *
 * @argc: argument count
 * @argv: argument vector
 * @flagnojail: non-zero to skip the network jail
 *
 * Parses wrapper options, starts helper processes, configures TLS, and
 * then forwards bytes between standard input/output, the TLS engine, and
 * the wrapped child process until one side closes or a signal arrives.
 *
 * Constraints:
 *   - argv must contain at least one certificate source and a child command
 */
int main_tlswrapper(int argc, char **argv, int flagnojail) {

    char *x;
    int flaguserreported = 0;
    long long r;

    errno = 0;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, signalhandler);
    signal(SIGTERM, signalhandler);
    alarm(starttimeout);

    log_set_name("tlswrapper");
    log_unset_id();

    /* initialize default cipher suites */
    tls_cipher_defaults(&ctx);

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

            /* server preferences */
            if (*x == 's') { ctx.flags |= tls_flags_ENFORCE_SERVER_PREFERENCES; continue; }
            if (*x == 'S') { ctx.flags &= ~tls_flags_ENFORCE_SERVER_PREFERENCES; continue; }

            /* proxy-protocol */
            if (*x == 'p') {
                if (x[1]) { pp_incoming(x + 1); break; }
                if (argv[1]) { pp_incoming(*++argv); break; }
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
            /* delayed encryption */
            if (*x == 'n') { ctx.flagdelayedenc = 1; continue; }
            if (*x == 'N') { ctx.flagdelayedenc = 0; continue; }

            usage();
        }
    }
    if (!*++argv) usage();
    if (!ctx.certfiles_len) usage();
    if (userfromcert && !ctx.anchorfn) die_optionUa();
    if (userfromcert && ctx.flagdelayedenc) die_optionUn();
    timeout = timeout_parse(timeoutstr);
    hstimeout = timeout_parse(hstimeoutstr);

    /* set flagnojail */
    ctx.flagnojail = flagnojail;


    /* create control pipe  */
    if (ctx.flagdelayedenc) {
        struct stat st;
        if (fstat(CONTROLPIPEFD, &st) != -1) die_controlpipe();
        for (;;) {
            r = open_read("/dev/null");
            if (r == -1) die_devnull();
            if (r > CONTROLPIPEFD) { close(r); break; }
        }
    }

    /* run child process */
    if (open_pipe(tochild) == -1) die_pipe();
    if (open_pipe(fromchild) == -1) die_pipe();
    if (open_pipe(fromchildcontrol) == -1) die_pipe();
    child = fork();
    switch (child) {
        case -1:
            die_fork();
        case 0:
            alarm(0);

            close(tochild[1]);
            close(0);
            if (dup(tochild[0]) != 0) die_dup();
            blocking_enable(0);

            close(fromchild[0]);
            close(1);
            if (dup(fromchild[1]) != 1) die_dup();
            blocking_enable(1);

            close(fromchildcontrol[0]);
            close(CONTROLPIPEFD);
            if (ctx.flagdelayedenc) {
                if (dup(fromchildcontrol[1]) != CONTROLPIPEFD) die_dup();
                blocking_enable(CONTROLPIPEFD);
            }

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
    close(fromchildcontrol[1]);
    close(fromchild[1]);
    close(tochild[0]);
    log_t2("child pid ", log_num(child));

    controlfd = fromchildcontrol[0];
    childoutfd = fromchild[0];
    childinfd = tochild[1];
    blocking_disable(controlfd);
    blocking_disable(childoutfd);
    blocking_disable(childinfd);

    /* initialize randombytes */
    {
        char ch[1];
        randombytes(ch, sizeof ch);
    }

    /* run service process for loading keys and secret-key operations */
    if (open_pipe(fromkeyjail) == -1) die_pipe();
    if (open_pipe(tokeyjail) == -1) die_pipe();
    keyjailchild = fork();
    switch (keyjailchild) {
        case -1:
            die_fork();
        case 0:
            alarm(0);
            close(fromkeyjail[0]);
            close(tokeyjail[1]);
            close(controlfd);
            close(childoutfd);
            close(childinfd);
            close(0);
            if (dup(tokeyjail[0]) != 0) die_dup();
            close(1);
            if (dup(fromkeyjail[1]) != 1) die_dup();
            blocking_enable(0);
            blocking_enable(1);
            signal(SIGPIPE, SIG_IGN);
            signal(SIGCHLD, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            log_set_ip(0);
            tls_keyjail(&ctx);
            die(0);
    }
    close(fromkeyjail[1]);
    close(tokeyjail[0]);
    log_t2("keyjail pid ", log_num(keyjailchild));
    blocking_enable(fromkeyjail[0]);
    blocking_enable(tokeyjail[1]);
    tls_pipe_fromchild = fromkeyjail[0];
    tls_pipe_tochild = tokeyjail[1];
    tls_pipe_set_engine(&ctx);

    /* create selfpipe */
    if (open_pipe(selfpipe) == -1) die_pipe();
    blocking_enable(selfpipe[1]);

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
        if (pipe_write(tls_pipe_tochild, ctx.anchorfn, str_len(ctx.anchorfn) + 1) == -1) die_writetopipe();
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
    log_set_ip(iptostr(remoteipstr, remoteip));
    log_t4("connection local=", log_ipport(localip, localport),
           " remote=", log_ipport(remoteip, remoteport));

    /* non-blocking stdin/stdout */
    netinfd = 0;
    netoutfd = 1;
    blocking_disable(netinfd);
    blocking_disable(netoutfd);

    log_d1("start");

    /* write connection info to the child */
    if (pipe_write(childinfd, localip, sizeof localip) == -1) die_writetopipe();
    if (pipe_write(childinfd, localport, sizeof localport) == -1) die_writetopipe();
    if (pipe_write(childinfd, remoteip, sizeof remoteip) == -1) die_writetopipe();
    if (pipe_write(childinfd, remoteport, sizeof remoteport) == -1) die_writetopipe();

    if (ctx.flagdelayedenc) {
        /* Child expects the one-shot login/account record before STARTTLS too.
         * Send an empty placeholder now and mark it as already delivered so
         * report_tls_handshake() does not inject a second record later. */
        report_tls_user("", &flaguserreported);
        log_t1("sent empty pre-STARTTLS user record");
    }
    else {
        close_rfd(&controlfd);
    }

    if (ctx.flagdelayedenc) {
        if (!run_cleartext_phase()) goto waitchildren;
        ctx.flagdelayedenc = 0;
        ctx.flaghandshakedone = 0;
        alarm(hstimeout);
        log_t1("switching from cleartext to tls");
    }

    /* TLS init */
    tls_profile(&ctx);
    log_t1("tls profile initialized");
    run_tls_phase(&flaguserreported);

waitchildren:
    signal(SIGCHLD, SIG_DFL);
    signal(SIGALRM, SIG_DFL);
    close_rfd(&controlfd);

    /* wait for keyjail child */
    close(fromkeyjail[0]);
    close(tokeyjail[1]);
    do {
        r = waitpid(keyjailchild, &status, 0);
    } while (r == -1 && errno == EINTR);
    if (!WIFEXITED(status)) {
        log_t2("keyjail process killed by signal ", log_num(WTERMSIG(status)));
    }
    else {
        log_t2("keyjail exited with status ", log_num(WEXITSTATUS(status)));
    }

    /* wait for child */
    close_rfd(&childoutfd);
    (void) close_wfd(&childinfd);
    do {
        r = waitpid(child, &status, 0);
    } while (r == -1 && errno == EINTR);
    errno = 0;
    if (!WIFEXITED(status)) {
        log_f2("child process killed by signal ", log_num(WTERMSIG(status)));
        die(111);
    }
    log_d2("child exited with status ", log_num(WEXITSTATUS(status)));
    die(WEXITSTATUS(status));
}

/* clang-format on */
