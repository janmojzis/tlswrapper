#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include "randombytes.h"
#include "sio.h"
#include "commands.h"
#include "log.h"
#include "open.h"
#include "stralloc.h"
#include "e.h"
#include "blocking.h"
#include "iptostr.h"
#include "connectioninfo.h"
#include "main.h"

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
#define die_readchild() { log_f1("unable to read from child"); die(111); }
#define die_read() { log_f1("unable to read from standart input"); die(111); }
#define die_devnull() { log_f1("unable to open /dev/null"); die(111); }

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

static void get(unsigned char *ch) {

    sio_getch(&scin, (char *)ch);
}

static void outs(char *x, char *y) {

    sio_puts(&scout, x);
    if (y) {
        sio_putch(&scout, ' ');
        sio_puts(&scout, y);
    }
    sio_puts(&scout, "\r\n");
    sio_flush(&scout);
}

static long long smtpcode(int replace) {

    unsigned char ch;
    unsigned long long code;

    get(&ch); code = ch - '0';
    sio_putch(&sout, (char )ch);
    get(&ch); code = code * 10 + (ch - '0');
    sio_putch(&sout, (char )ch);
    get(&ch); code = code * 10 + (ch - '0');
    sio_putch(&sout, (char )ch);
    for (;;) {
        get(&ch);
        if (replace && code == 250 && ch == ' ') {
            sio_putch(&sout, (char)'-');
        }
        else {
            sio_putch(&sout, (char )ch);
        }
        if (ch != '-') break;
        while (ch != '\n') { get(&ch); sio_putch(&sout, (char )ch); }
        get(&ch);
        sio_putch(&sout, (char )ch);
        get(&ch);
        sio_putch(&sout, (char )ch);
        get(&ch);
        sio_putch(&sout, (char )ch);
    }
    while (ch != '\n') { get(&ch); sio_putch(&sout, (char )ch); }
    return code;
}

static void smtp_greet(void) {
    long long code;
    code = smtpcode(0);
    sio_flush(&sout);
    log_d2("greet: ", lognum(code));
}

static long long smtpcmd(char *x, char *y) { 

    long long code;

    outs(x, y);
    code = smtpcode(0);
    sio_flush(&sout);
    return code;
}

static stralloc logline = {0};

static long long smtp_mail(char *x, char *y) {

    long long code;

    outs(x, y);
    code = smtpcode(0);
    sio_flush(&sout);
    if (!stralloc_copys(&logline, y)) die_nomem();
    if (!stralloc_cats(&logline, ", ")) die_nomem();
    return code;
}

static long long smtp_rcpt(char *x, char *y) {

    long long code;

    outs(x, y);
    code = smtpcode(0);
    sio_flush(&sout);
    if (!stralloc_cats(&logline, y)) die_nomem();
    if (!stralloc_cats(&logline, ": ")) die_nomem();
    return code;
}

static long long smtp_ehlo(char *x, char *y) {

    long long code;
    struct stat st;

    outs(x, y);
    if (fstat(5, &st) == -1) {
        code = smtpcode(0);
    }
    else {
        code = smtpcode(1);
        if (code == 250) {
            sio_puts(&sout, "250 STARTTLS\r\n");
        }
    }
    sio_flush(&sout);
    return code;
}

static long long smtp_starttls(char *x, char *y) {

    struct stat st;

    (void) x;
    (void) y;

    if (fstat(5, &st) == -1) {
        sio_puts(&sout, "553 sorry, can't start TLS again\r\n");
        sio_flush(&sout);
        return 553;
    }

    sio_puts(&sout5, "220 ready to start TLS\r\n");
    sio_flush(&sout5);
    close(5);
    return 220;
}

static stralloc line = {0};
static void getln(void) {

    if (!stralloc_copys(&line, "")) die_nomem();

    for (;;) {
      long long i;
      char ch;
      i = sio_getch(&sin, &ch);
      if (i != 1) die_read();
      if (ch == '\n') break;
      if (!ch) ch = '\n';
      if (!stralloc_append(&line,&ch)) die_nomem();
    }
    if (line.len > 0) if (line.s[line.len - 1] == '\r') --line.len;
	if (!stralloc_0(&line)) die_nomem();
	--line.len;
}

static long long smtp_data(char *x, char *y) {

    long long code;

    outs(x, y);
    code = smtpcode(0);
    sio_flush(&sout);
    if (code != 354) return code;
    for (;;) {
        getln();
		sio_puts(&scout, line.s);
        sio_puts(&scout, "\r\n");
        if ((line.len == 1) && line.s[0] == '.') {
			break;
        }
    }
    sio_flush(&scout);
    code = smtpcode(0);
    sio_flush(&sout);
    if (!stralloc_catnum(&logline, code)) die_nomem();
    if (!stralloc_0(&logline)) die_nomem();
    if (code == 250) {
        log_i1(logline.s);
    }
    else {
        log_w1(logline.s);
    }
    return code;
}

static long long smtp_quit(char *x, char *y) {

    long long code;

    outs(x, y);
    code = smtpcode(0);
    sio_flush(&sout);
    log_d3(x, ": ", lognum(code));
    die(0);
    return 0; /* make compiler happy */
}

static struct commands smtpcommands[] = {
  { "mail", smtp_mail, 0 }
, { "rcpt", smtp_rcpt, 0 }
, { "ehlo", smtp_ehlo, 0 }
, { "data", smtp_data, 0 }
, { "starttls", smtp_starttls, 0 }
, { "quit", smtp_quit, 0 }
, { 0, smtpcmd, 0 }
} ;

int main_tlswrapper_smtp(int argc, char **argv) {

    char *x;
    struct stat st;

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

    connectioninfo_get(localip, localport, remoteip, remoteport);
    log_ip(iptostr(remoteipstr, remoteip));

    smtp_greet();
    commands(&sin, smtpcommands);

    return 0;
}
