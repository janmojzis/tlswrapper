#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include "randombytes.h"
#include "sio.h"
#include "log.h"
#include "open.h"
#include "stralloc.h"
#include "e.h"
#include "blocking.h"
#include "iptostr.h"
#include "connectioninfo.h"
#include "case.h"
#include "alloc.h"
#include "jail.h"
#include "main.h"

static const char *jailaccount = 0;
static const char *jaildir = EMPTYDIR;
static const char *user = 0;

static int flagverbose = 1;
static int flagdie = 0;

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
    alloc_freeall();
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
#define die_jail() { log_f1("unable to create jail"); die(111); }
#define die_droppriv(x) { log_f3("unable to drop privileges to '", (x), "'"); die(111); }

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
static char outbuf[8192];
static sio sout = sio_INIT(_write, 1, outbuf, sizeof outbuf);
static char outbuf5[32];
static sio sout5 = sio_INIT(_write, 5, outbuf5, sizeof outbuf5);
static char cinbuf[8192];
static sio scin;
static char coutbuf[8192];
static sio scout;


static void usage(void) {
    log_u1("tlswrapper-smtp [options] child");
    die(100);
}

static stralloc logmail = {0};
static stralloc logcode = {0};
static stralloc logline = {0};
static stralloc line = {0};

static void get(unsigned char *ch) {
    sio_getch(&scin, (char *)ch);
    if (!stralloc_append(&logcode, ch)) die_nomem();
}
static void out(unsigned char ch) {
    sio_putch(&sout, (char) ch);
}
static void outs(char *x) {
    sio_puts(&sout, x);
}
static void flush(void) {
    sio_flush(&sout);
}
static long long smtpcode(char *append) {

    unsigned char ch;
    unsigned long long code;

    if (!stralloc_copys(&logcode, "")) die_nomem();

    get(&ch); out(ch); code = ch - '0';
    get(&ch); out(ch); code = code * 10 + (ch - '0');
    get(&ch); out(ch); code = code * 10 + (ch - '0');
    for (;;) {
        get(&ch);
        if (append && code == 250 && ch == ' ') {
            out('-');
        }
        else {
            out(ch);
        }
        if (ch != '-') break;
        while (ch != '\n') { get(&ch); out(ch); }
        get(&ch); out(ch);
        get(&ch); out(ch);
        get(&ch); out(ch);
    }
    while (ch != '\n') { get(&ch); out(ch); }
    if (append && code == 250) outs(append);
    flush();
    if (!stralloc_0(&logcode)) die_nomem();
    return code;
}

static void readline(void) {

    if (!stralloc_copys(&line, "")) die_nomem();

    for (;;) {
      char ch;
      (void) sio_getch(&sin, &ch);
      if (ch == '\n') break;
      if (!ch) ch = '\n';
      if (!stralloc_append(&line,&ch)) die_nomem();
    }
    if (line.len > 0) if (line.s[line.len - 1] == '\r') --line.len;
	if (!stralloc_0(&line)) die_nomem();
	--line.len;
    log_t3("line: '", line.s, "'");
}

int main_tlswrapper_smtp(int argc, char **argv) {

    char *x;
    struct stat st;
    long long code;

    signal(SIGPIPE, SIG_IGN);
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
            /* jail */
            if (*x == 'J') {
                if (x[1]) { jaildir = (x + 1); break; }
                if (argv[1]) { jaildir = (*++argv); break; }
            }
            if (*x == 'j') {
                if (x[1]) { jailaccount = (x + 1); break; }
                if (argv[1]) { jailaccount = (*++argv); break; }
            }
			/* user */
            if (*x == 'u') {
                if (x[1]) { user = x + 1; break; }
                if (argv[1]) { user = *++argv; break; }
            }
            usage();
        }
    }
    if (!*++argv) usage();

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

    alarm(1200);

    /* initialize randombytes */
    {
        char ch[1];
        randombytes(ch, sizeof ch);
    }

    if (jail(jailaccount, jaildir, 1) == -1) die_jail();

    connectioninfo_get(localip, localport, remoteip, remoteport);
    log_ip(iptostr(remoteipstr, remoteip));

    (void) smtpcode(0);
    while (!flagdie) {
        readline();
        if (!stralloc_copy(&logline, &line)) die_nomem();
        if (!stralloc_0(&logline)) die_nomem();
        if (case_startb(line.s, line.len, "data")) {
            sio_puts(&scout, line.s);
            sio_puts(&scout, "\r\n");
            sio_flush(&scout);
            if (smtpcode(0) != 354) {
                log_w3(logmail.s, ": ", logcode.s);
                log_d3(logline.s, ": ", logcode.s);
                continue;
            }
            for (;;) {
                readline();
                sio_puts(&scout, line.s);
                sio_puts(&scout, "\r\n");
                if ((line.len == 1) && line.s[0] == '.') {
                    break;
                }
            }
            sio_flush(&scout);
            code = smtpcode(0);
            log_d3(logline.s, ": ", logcode.s);
            if (code != 250) {
                log_w3(logmail.s, ": ", logcode.s);
            }
            else {
                log_i3(logmail.s, ": ", logcode.s);
            }
            continue;
        }
        if (case_startb(line.s, line.len, "ehlo")) {
            sio_puts(&scout, line.s);
            sio_puts(&scout, "\r\n");
            sio_flush(&scout);
            if (fstat(5, &st) == -1) {
                (void) smtpcode(0);
            }
            else {
                (void) smtpcode("250 STARTTLS\r\n");
            }
            errno = 0;
            log_d3(logline.s, ": ", logcode.s);
            continue;
        }
        if (case_startb(line.s, line.len, "starttls")) {
            if (fstat(5, &st) == -1) {
                sio_puts(&sout, "553 sorry, can't start TLS again\r\n");
                sio_flush(&sout);
                log_d2(logline.s, ": 553 sorry, can't start TLS again");
                errno = 0;
                continue;
            }
#define TLSMSG "220 ready to start TLS\r\n"
            sio_puts(&sout5, TLSMSG);
            sio_flush(&sout5);
            close(5);
            log_d3(logline.s, ": ", TLSMSG);

            sio_puts(&scout, "RSET\r\n");
            sio_flush(&scout);
            if (!stralloc_copys(&logcode, "")) die_nomem();
            for (;;) {
                unsigned char ch;
                get(&ch);
                if (ch == '\n') break;
            }
            if (!stralloc_0(&logcode)) die_nomem();
            log_d2("RSET: ", logcode.s);
            continue;
        }
        if (case_startb(line.s, line.len, "quit")) {
            flagdie = 1;
            alarm(1);
        }
        if (case_startb(line.s, line.len, "mail ")) {
            if (!stralloc_copyb(&logmail, line.s + 5, line.len - 5)) die_nomem();
            if (!stralloc_cats(&logmail, ", ")) die_nomem();
            sio_puts(&scout, line.s);
            sio_puts(&scout, "\r\n");
            sio_flush(&scout);
            log_d3(logline.s, ": ", logcode.s);
            if (smtpcode(0) != 250) {
                if (!stralloc_0(&logmail)) die_nomem();
                log_w3(logmail.s, ": ", logcode.s);
            }
            continue;
        }
        if (case_startb(line.s, line.len, "rcpt ")) {
            if (!stralloc_catb(&logmail, line.s + 5, line.len - 5)) die_nomem();
            if (!stralloc_0(&logmail)) die_nomem();
            sio_puts(&scout, line.s);
            sio_puts(&scout, "\r\n");
            sio_flush(&scout);
            log_d3(logline.s, ": ", logcode.s);
            if (smtpcode(0) != 250) {
                log_w3(logmail.s, ": ", logcode.s);
            }
            continue;
        }
        sio_puts(&scout, line.s);
        sio_puts(&scout, "\r\n");
        sio_flush(&scout);
        (void) smtpcode(0);
        log_d3(logline.s, ": ", logcode.s);
    }

    die(0);
    return 0;
}
