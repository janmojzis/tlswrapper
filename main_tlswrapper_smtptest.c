#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include "randombytes.h"
#include "commands.h"
#include "log.h"
#include "open.h"
#include "stralloc.h"
#include "e.h"
#include "blocking.h"
#include "sio.h"
#include "main.h"

#include <string.h>
#include "writeall.h"

static int flagverbose = 1;


static void cleanup(void) {
    {
        unsigned char stack[4096];
        randombytes(stack, sizeof stack);
    }
}

#define die(x) { cleanup(); _exit(x); }
#define die_jail() { log_f1("unable to create jail"); die(111); }
#define die_pipe() { log_f1("unable to create pipe"); die(111); }
#define die_fork() { log_f1("unable to fork"); die(111); }
#define die_dup() { log_f1("unable to dup"); die(111); }
#define die_nomem() { log_f1("unable to allocate memory"); die(111); }
#define die_read() { log_f1("unable to read from child"); die(111); }


static long long _write(int fd, void *xv, long long xlen) {
    long long w = sio_write(fd, xv, xlen);
    if (w <= 0) {
        log_f1("write failed");
        die(1);
    }
    return w;
}

static long long _read(int fd, void *xv, long long xlen) {
    long long r = sio_read(fd, xv, xlen);
    if (r <= 0) {
        log_f1("read failed");
        die(1);
    }
    return r;
}

static char inbuf[1024];
static sio sin = sio_INIT(_read, 0, inbuf, sizeof inbuf);
static char outbuf[1024];
static sio sout = sio_INIT(_write, 1, outbuf, sizeof outbuf);


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
}


static void usage(void) {
    log_u1("tlswrapper-smtp [options] child");
    die(100);
}

static void outs(char *x) {

    sio_puts(&sout, x);
    sio_flush(&sout);
}

static void greet(char *x, char *y) { 
    (void) x;
    (void) y;
    outs("220 test\r\n");
}

static void accept(char *x, char *y) { 
    (void) x;
    (void) y;
    outs("250 test\r\n");
}

static void reject(char *x, char *y) { 
    (void) x;
    (void) y;
    outs("553 test\r\n");
}

static void quit(char *x, char *y) { 
    (void) x;
    (void) y;
    die(0);
}

static void data(char *x, char *y) {
    (void) x;
    (void) y;
    outs("354 test\r\n");
    for (;;) {
        getln();
        if ((line.len == 1) && line.s[0] == '.') {
            outs("250 test\r\n");
            return;
        }
    }
}

static struct commands smtpcommands[] = {
  { "quit", quit, 0 }
, { "helo", accept, 0 }
, { "ehlo", accept, 0 }
, { "mail", accept, 0 }
, { "rset", accept, 0 }
, { "noop", accept, 0 }
, { "data", data, 0 }
, { 0, reject, 0 }
} ;

int main_tlswrapper_smtptest(int argc, char **argv) {

    char *x;

    signal(SIGPIPE, SIG_IGN);

    log_name("tlswrapper-smtptest");
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

    greet(0, 0);
    commands(&sin, smtpcommands);

    return 0;
}
