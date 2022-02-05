#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include "randombytes.h"
#include "log.h"
#include "iptostr.h"
#include "connectioninfo.h"
#include "jail.h"
#include "writeall.h"
#include "sio.h"
#include "stralloc.h"
#include "open.h"
#include "e.h"
#include "tls.h"
#include "blocking.h"
#include "resolvehost.h"
#include "hostport.h"
#include "conn.h"
#include "case.h"
#include "main.h"

/* clang-format off */

static const char *jailaccount = 0;
static const char *jaildir = EMPTYDIR;
static const char *user = 0;

static int flagverbose = 1;

static int fromchild[2] = {-1, -1};
static int tochild[2] = {-1, -1};
static pid_t child = -1;
static int status;

static unsigned char localip[16] = {0};
static unsigned char localport[2] = {0};
static unsigned char remoteip[16] = {0};
static unsigned char remoteport[2] = {0};
static char remoteipstr[IPTOSTR_LEN] = {0};

static void cleanup(void) {
    randombytes(localip, sizeof localip);
    randombytes(localport, sizeof localport);
    randombytes(remoteip, sizeof remoteip);
    randombytes(remoteip, sizeof remoteip);
    {
        unsigned char stack[4096];
        randombytes(stack, sizeof stack);
    }
}

static void die(int x) {

    int r;

    /* cleanup */
    cleanup();
    if (child == -1) _exit(x);
    if (x != 0) _exit(x);

    /* wait for child */
    close(fromchild[0]);
    close(tochild[1]);
    do {
        r = waitpid(child, &status, 0);
    } while (r == -1 && errno == EINTR);
    errno = 0;
    if (!WIFEXITED(status)) {
        log_f2("child process killed by signal ", lognum(WTERMSIG(status)));
        _exit(111);
    }
    log_d2("child exited with status ", lognum(WEXITSTATUS(status)));
    _exit(WEXITSTATUS(status));
}

#define die_jail() { log_f1("unable to create jail"); die(111); }
#define die_pipe() { log_f1("unable to create pipe"); die(111); }
#define die_fork() { log_f1("unable to fork"); die(111); }
#define die_dup() { log_f1("unable to dup"); die(111); }
#define die_nomem() { log_f1("unable to allocate memory"); die(111); }
#define die_droppriv(x) { log_f3("unable to drop privileges to '", (x), "'"); die(111); }


static void usage(void) {
    log_u1("tlswrapper-smtp [options] child");
    die(100);
}

static const char *timeoutstr = "600";
static const char *connecttimeoutstr = "10";
static long long timeout;
static long long connecttimeout;

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

static void signalhandler(int signum) {
    (void) signum;
    die(111);
}

static long long _write(int fd, void *xv, long long xlen) {
    long long w = sio_write(fd, xv, xlen);
    if (w <= 0) {
        log_d1("write failed");
        die(111);
    }
    return w;
}

static long long _read(int fd, void *xv, long long xlen) {

    long long r = sio_read(fd, xv, xlen);
    if (r <= 0) {
        log_d1("read failed");
        die(111);
    }
    return r;
}

static char inbuf[8192];
static sio sin = sio_INIT(_read, 0, inbuf, sizeof inbuf);
static char outbuf[128];
static sio sout = sio_INIT(_write, 1, outbuf, sizeof outbuf);
static char outbuf5[32];
static sio sout5 = sio_INIT(_write, 5, outbuf5, sizeof outbuf5);
static char cinbuf[128];
static sio scin;
static char coutbuf[8192];
static sio scout;

static stralloc line = {0};
static stralloc cline = {0};

static stralloc mailfrom = {0};
static stralloc rcptto = {0};
static stralloc rcpttodata = {0};


static int _catlogid(stralloc *sa) {

    if (log_getid()) {
        if (!stralloc_cats(sa, " [")) return 0;
        if (!stralloc_cats(sa, log_getid())) return 0;
        if (!stralloc_cats(sa, "]")) return 0;
    }
    return 1;
}


static stralloc greylistresp = {0};
static const char *greylistmsg = 0;
static char *greylisthostport = 0;
static char greylisthost[256];
static unsigned char greylistport[2];
static unsigned char greylistip[16];
static long long greylistiplen;
static int greylistfd = -1;
static char greylistbuf[256];

static const char *greylist(void) {

    char ch;

    sio gsin;
    sio_init(&gsin, _write, greylistfd, greylistbuf, sizeof greylistbuf);

    sio_puts(&gsin, "request=smtpd_access_policy\n");
    sio_puts(&gsin, "client_address=");
    sio_puts(&gsin, remoteipstr);
    sio_puts(&gsin, "\nsender=");
    sio_puts(&gsin, mailfrom.s);
    sio_puts(&gsin, "\nrecipient=");
    sio_puts(&gsin, rcptto.s);
    sio_puts(&gsin, "\n\n");
    sio_flush(&gsin);

    sio_init(&gsin, _read, greylistfd, greylistbuf, sizeof greylistbuf);

    do {
        sio_getch(&gsin, &ch);
        if (!stralloc_append(&greylistresp, &ch)) die_nomem();
    } while (ch != '\n');
    if (!stralloc_0(&greylistresp)) die_nomem();
    log_t2("greylist: ", greylistresp.s);
    if (greylistresp.len >= 12) {
        if (!case_diffb(greylistresp.s, 12, "action=dunno")) {
            return 0;
        }
    }
    if (greylistresp.len >= 13) {
        if (!case_diffb(greylistresp.s, 13, "action=reject")) {
            return "553 bad reputation (#5.7.1)";
        }
    }
    return "450 greylisted (#4.3.0)";
}


static long long smtpline(char *append, int addlogid) {

    unsigned char ch;
    unsigned long long code;

    if (!stralloc_copys(&cline, "")) die_nomem();

    sio_getch(&scin, (char *)&ch); code = ch - '0';
    if (!stralloc_append(&cline, &ch)) die_nomem();
    sio_getch(&scin, (char *)&ch); code = code * 10 + (ch - '0');
    if (!stralloc_append(&cline, &ch)) die_nomem();
    sio_getch(&scin, (char *)&ch); code = code * 10 + (ch - '0');
    if (!stralloc_append(&cline, &ch)) die_nomem();

    for (;;) {
        sio_getch(&scin, (char *)&ch);
        if (append && code == 250 && ch == ' ') {
            if (!stralloc_cats(&cline, "-")) die_nomem();
        }
        else {
            if (!stralloc_append(&cline, &ch)) die_nomem();
        }
        if (ch != '-') break;
        while (ch != '\n') {
            sio_getch(&scin, (char *)&ch);
            if (!stralloc_append(&cline, &ch)) die_nomem();
        }
        sio_getch(&scin, (char *)&ch);
        if (!stralloc_append(&cline, &ch)) die_nomem();
        sio_getch(&scin, (char *)&ch);
        if (!stralloc_append(&cline, &ch)) die_nomem();
        sio_getch(&scin, (char *)&ch);
        if (!stralloc_append(&cline, &ch)) die_nomem();
    }
    while (ch != '\n') {
        sio_getch(&scin, (char *)&ch);
        if (!stralloc_append(&cline, &ch)) die_nomem();
    }
    if (append && code == 250) if (!stralloc_cats(&cline, append)) die_nomem();
    if (!stralloc_0(&cline)) die_nomem();
    --cline.len;
    log_t3("child line: '", cline.s, "'");

    /* add logid */
    if (addlogid && log_getid()) {
        if (cline.len > 0) if (cline.s[cline.len - 1] == '\n') --cline.len;
        if (cline.len > 0) if (cline.s[cline.len - 1] == '\r') --cline.len;
        if (!_catlogid(&cline)) die_nomem();
        if (!stralloc_cats(&cline, "\r\n")) die_nomem();
        if (!stralloc_0(&cline)) die_nomem();
        --cline.len;
        log_t3("child line with logid: '", cline.s, "'");
    }
    return code;
}

static void readline(void) {

    if (!stralloc_copys(&line, "")) die_nomem();

    for (;;) {
      char ch;
      sio_getch(&sin, &ch);
      if (ch == '\n') break;
      if (!ch) ch = '\n';
      if (!stralloc_append(&line, &ch)) die_nomem();
    }
    if (line.len > 0) if (line.s[line.len - 1] == '\r') --line.len;
    if (!stralloc_cats(&line, "\r\n")) die_nomem();
    if (!stralloc_0(&line)) die_nomem();
    --line.len;
    log_t3("line: '", line.s, "'");
}

struct commands {
    char *verb;
    void (*action)(void);
};

static void commands(struct commands *c) {

    long long i, len;

    for (;;) {
        readline();

        for (len = 0; len < line.len; ++len) {
            if (line.s[len] == ' ') break;
            if (line.s[len] == '\r') break;
            if (line.s[len] == '\n') break;
        }

        for (i = 0; c[i].verb; ++i) {
            if (!case_diffb(line.s, len, c[i].verb)) break;
        }
        c[i].action();
    }
}

static void smtp_greet(void) {

    smtpline(0, 1);
    sio_putsflush(&sout, cline.s);
}

static long long copy(int logid) {

    long long code;

    sio_putsflush(&scout, line.s);
    code = smtpline(0, logid);
    sio_putsflush(&sout, cline.s);
    log_d3(line.s, ": ", cline.s);
    return code;
}

static void smtp_default(void) {
    copy(0);
}

static void smtp_quit(void) {
    copy(1);
    die(0);
}

static void smtp_data(void) {

    long long code;

    sio_putsflush(&scout, line.s);
    code = smtpline(0, 1);
    sio_putsflush(&sout, cline.s);
    if (code != 354) {
        log_d3(line.s, ": ", cline.s);
        log_w6("F=", mailfrom.s, " T=", rcpttodata.s, ": ", cline.s);
        return;
    }

    for (;;) {
        readline();
        sio_puts(&scout, line.s);
        if (line.len > 0) if (line.s[line.len - 1] == '\n') --line.len;
        if (line.len > 0) if (line.s[line.len - 1] == '\r') --line.len;
        if ((line.len == 1) && line.s[0] == '.') break;
    }
    sio_flush(&scout);
    code = smtpline(0, 1);
    sio_putsflush(&sout, cline.s);
    log_d2("DATA: ", cline.s);
    if (code != 250) {
        log_w6("F=", mailfrom.s, " T=", rcpttodata.s, ": ", cline.s);
    }
    else {
        log_i6("F=", mailfrom.s, " T=", rcpttodata.s, ": ", cline.s);
    }
}

static void smtp_mail(void) {

    long long code, i;

    if (line.len >= 10) {
        if (!case_diffb(line.s, 10, "mail from:")) {
            if (!stralloc_copyb(&mailfrom, line.s + 10, line.len - 10)) die_nomem();
            if (mailfrom.s[mailfrom.len - 1] == '\n') --mailfrom.len;
            if (mailfrom.s[mailfrom.len - 1] == '\r') --mailfrom.len;
            for (i = 0; i < mailfrom.len; ++i) {
                if (mailfrom.s[i] == ' ') mailfrom.len = i;
            }
            if (!stralloc_0(&mailfrom)) die_nomem();
        }
    }

    code = copy(1);
    if (code != 250) {
        log_w4("F=", mailfrom.s, ": ", cline.s);
    }
}

static void smtp_rcpt(void) {

    long long code, i;

    if (line.len >= 8) {
        if (!case_diffb(line.s, 8, "rcpt to:")) {
            if (!stralloc_copyb(&rcptto, line.s + 8, line.len - 8)) die_nomem();
            if (rcptto.s[rcptto.len - 1] == '\n') --rcptto.len;
            if (rcptto.s[rcptto.len - 1] == '\r') --rcptto.len;
            for (i = 0; i < rcptto.len; ++i) {
                if (rcptto.s[i] == ' ') {
                    rcptto.len = i;
                    break;
                }
            }
            if (!stralloc_cat(&rcpttodata, &rcptto)) die_nomem();
            if (!stralloc_cats(&rcpttodata, ",")) die_nomem();
            if (!stralloc_0(&rcptto)) die_nomem();
            if (!stralloc_0(&rcpttodata)) die_nomem();
            --rcpttodata.len;
        }
    }

    if (mailfrom.len && rcptto.len && greylistfd != -1) {
        greylistmsg = greylist();
        if (greylistmsg) {
            if (!stralloc_copys(&cline, greylistmsg)) die_nomem();
            if (!_catlogid(&cline)) die_nomem();
            if (!stralloc_cats(&cline, "\r\n")) die_nomem();
            if (!stralloc_0(&cline)) die_nomem();
            sio_putsflush(&sout, cline.s);
            log_d3(line.s, ": ", cline.s);
            log_w6("F=", mailfrom.s, " T=", rcptto.s, ": ", cline.s);
            return;
        }
    }

    code = copy(1);
    if (code != 250) {
        log_w6("F=", mailfrom.s, " T=", rcptto.s, ": ", cline.s);
    }
}

static void smtp_ehlo(void) {

    struct stat st;

    sio_putsflush(&scout, line.s);
    if (fstat(5, &st) == -1) {
        (void) smtpline(0, 0);
    }
    else {
        (void) smtpline("250 STARTTLS\r\n", 0);
    }
    errno = 0;
    sio_putsflush(&sout, cline.s);
    log_d3(line.s, ": ", cline.s);
}

static void smtp_starttls(void) {

    struct stat st;

    if (fstat(5, &st) == -1) {
        if (!stralloc_copys(&cline, "553 sorry, can't start TLS again")) die_nomem();
        if (!_catlogid(&cline)) die_nomem();
        if (!stralloc_cats(&cline, "\r\n")) die_nomem();
        if (!stralloc_0(&cline)) die_nomem();
        sio_putsflush(&sout, cline.s);
        log_d3(line.s, ": ", cline.s);
        errno = 0;
        return;
    }

    if (!stralloc_copys(&cline, "220 ready to start TLS")) die_nomem();
    if (!_catlogid(&cline)) die_nomem();
    if (!stralloc_cats(&cline, "\r\n")) die_nomem();
    if (!stralloc_0(&cline)) die_nomem();

    sio_putsflush(&sout5, cline.s);
    close(5);
    log_d3(line.s, ": ", cline.s);

    sio_putsflush(&scout, "RSET\r\n");
    smtpline(0, 1);
}

struct commands smtpcommands[] = {
  { "quit", smtp_quit }
, { "data", smtp_data }
, { "mail", smtp_mail }
, { "rcpt", smtp_rcpt }
, { "ehlo", smtp_ehlo }
, { "starttls", smtp_starttls }
, { 0, smtp_default }
} ;



int main_tlswrapper_smtp(int argc, char **argv) {

    char *x;
    struct stat st;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, signalhandler);
    alarm(30);
    log_name("tlswrapper-smtp");
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
            /* user */
            if (*x == 'u') {
                if (x[1]) { user = x + 1; break; }
                if (argv[1]) { user = *++argv; break; }
            }
            /* timeouts */
            if (*x == 'T') {
                if (x[1]) { connecttimeoutstr =  x + 1; break; }
                if (argv[1]) { connecttimeoutstr = *++argv; break; }
            }
            if (*x == 't') {
                if (x[1]) { timeoutstr =  x + 1; break; }
                if (argv[1]) { timeoutstr = *++argv; break; }
            }
            /* greylist */
            if (*x == 'g') {
                if (x[1]) { greylisthostport =  x + 1; break; }
                if (argv[1]) { greylisthostport = *++argv; break; }
            }
            /* jail */
            if (*x == 'J') {
                if (x[1]) { jaildir = (x + 1); break; }
                if (argv[1]) { jaildir = (*++argv); break; }
            }
            if (*x == 'j') {
                if (x[1]) { jailaccount = (x + 1); break; }
                if (argv[1]) { jailaccount = (*++argv); break; }
            }
            usage();
        }
    }
    if (!*++argv) usage();
    timeout = timeout_parse(timeoutstr);
    connecttimeout = timeout_parse(connecttimeoutstr);
    if (greylisthostport) {
        if (!hostport_parse(greylisthost, sizeof greylisthost, greylistport, greylisthostport)) {
            log_f3("unable to parse greylist host:port from the string: '", greylisthostport, "'");
            die(100);
        }
        log_t5("greylist address '", greylisthost, ":", logport(greylistport), "'");
    }

    if (fstat(5, &st) == -1) {
        log_f1("please don't start tlswrapper-smtp directly");
        die(100);
    }


    /* run child process */
    if (open_pipe(tochild) == -1) die_pipe();
    if (open_pipe(fromchild) == -1) die_pipe();
    child = fork();
    switch (child) {
        case -1:
            die_fork();
            break;
        case 0:
            close(tochild[1]);
            close(0);
            if (dup(tochild[0]) != 0) die_dup();
            blocking_enable(0);

            close(fromchild[0]);
            close(1);
            if (dup(fromchild[1]) != 1) die_dup();
            blocking_enable(1);

            close(5);

            /* drop root */
            if (user) if (jail_droppriv(user) == -1) die_droppriv(user);

            signal(SIGPIPE, SIG_DFL);
            log_t3("running '", argv[0], "'");
            execvp(*argv, argv);
            log_f2("unable to run ", *argv);
            die(111);
    }
    close(fromchild[1]);
    close(tochild[0]);
    blocking_enable(fromchild[0]);
    blocking_enable(tochild[1]);
    sio_init(&scin, _read, fromchild[0], cinbuf, sizeof cinbuf);
    sio_init(&scout, _write, tochild[1], coutbuf, sizeof coutbuf);

    /* initialize randombytes */
    {
        char ch[1];
        randombytes(ch, sizeof ch);
    }

    if (greylisthostport) {
        if (!resolvehost_init()) {
            log_f1("unable to create jailed process for DNS resolver");
            die(111);
        }
        if (!conn_init(1)) {
            log_f1("unable to initalize TCP connection");
            die(111);
        }
    }

    /* create jail */
    if (jail(jailaccount, jaildir, 1) == -1) die_jail();

    if (greylisthostport) {
        greylistiplen = resolvehost_do(greylistip, sizeof greylistip, greylisthost);
        if (greylistiplen < 0) {
            log_f3("unable to resolve host '", greylisthost, "'");
            die(111);
        }
        if (greylistiplen == 0) {
            log_f3("unable to resolve host '", greylisthost, "': name not exist");
            die(111);
        }
        log_d4("resolvehost: ", greylisthost, ": ", logip(greylistip));
        resolvehost_close();

        greylistfd = conn(connecttimeout, greylistip, greylistiplen, greylistport);
        if (greylistfd == -1) {
            log_w2("unable to connect to ", greylisthostport);
        }
    }

    /* get connection info */
    (void) connectioninfo_get(localip, localport, remoteip, remoteport);
    log_ip(iptostr(remoteipstr, remoteip));

    /* initialize mailfrom, rcptto */
    if (!stralloc_0(&mailfrom)) die_nomem();
    --mailfrom.len;
    if (!stralloc_0(&rcptto)) die_nomem();
    --rcptto.len;
    if (!stralloc_0(&rcpttodata)) die_nomem();
    --rcpttodata.len;

    alarm(timeout);

    smtp_greet();

    commands(smtpcommands);
    die(111);
    return 111;
}

/* clang-format on */
