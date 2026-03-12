/*
 * log.c - Standard error logging module.
 *
 * The log library writes messages to standard error output (stderr).
 * Non-printable characters are escaped.
 *
 * Supported logging levels: usage, bug, fatal, error, warning, info, debug,
 * tracing.
 *
 * usage:   prints information about how to use the program
 * bug:     prints error messages about internal problems
 * fatal:   prints error messages that cause the program to terminate
 * error:   prints error messages that cause termination from lower-level code
 * warning: prints warning messages that do not cause the program to terminate
 * info:    prints informational messages under normal conditions
 * debug:   prints information useful for debugging problems
 * tracing: prints highly detailed debugging information
 *
 * Warning: Not thread-safe.
 *
 * Log format:
 * time: name: level: ip: message (error){file:function:line}[id]
 *
 * time ................ optional
 * name ................ optional
 * level ............... required
 * ip .................. optional
 * (error) ............. optional system error description
 * {file:function:line}  included only in debug/tracing verbosity levels
 * [id] ................ optional
 *
 */

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "e.h"
#include "log.h"

#define STATICBUFSIZE 68 /* space for '64 characters' + '...' + '\0' */

struct record_ {
    struct record_ *next;
    const char *name;
    long long namelen;
};

static struct record_ *head_ = 0;
static struct record_ *tail_ = 0;

int log_whitelist_add(const char *name) {

    struct record_ *r, *head;

    if (!name) return 0;

    r = malloc(sizeof(*r));
    if (!r) return 0;
    r->name = name;
    r->namelen = strlen(name);

    r->next = 0;
    if (head_) {
        head = head_;
        head->next = r;
    }
    head_ = r;
    if (!tail_) tail_ = r;

    return 1;
}

static int log_whitelist_match(const char *file, const char *fce) {

    struct record_ *r;
    long long filelen;

    (void) fce;
    if (!tail_) return 1;
    if (!file) return 1;

    filelen = strlen(file);

    for (r = tail_; r; r = r->next) {
        if (r->namelen > filelen) continue;
        if (!memcmp(file, r->name, r->namelen)) return 1;
    }
    return 0;
}

int log_level = log_level_FATAL;
static const char *logname = 0;
static int logtime = 0;
static long long loglimit = 200;
static const char *logipstr = 0;
static char logidbuf[STATICBUFSIZE];
static const char *logid = 0;
static int logcolor = 0;

void log_set_level(int level) {
    log_level = level;
    if (level < log_level_USAGE) log_level = log_level_USAGE;
    if (level > log_level_TRACING) log_level = log_level_TRACING;
}

void log_inc_level(int signal) {
    (void) signal;
    log_set_level(log_level + 1);
}

void log_dec_level(int signal) {
    (void) signal;
    log_set_level(log_level - 1);
}

void log_set_name(const char *name) { logname = name; }
void log_set_time(int flag) { logtime = flag; }
void log_set_color(int flag) { logcolor = flag; }
void log_set_ip(const char *ip) { logipstr = ip; }
void log_set_limit(long long limit) { loglimit = limit; }
const char *log_get_id(void) { return logid; }

static char buf[256];
static long long buflen = 0;

static void flush(void) {

    char *b = buf;
    long long r;

    while (buflen > 0) {
        r = write(2, b, (unsigned long long) buflen);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;
            if (errno == EWOULDBLOCK) continue;
            break;
        }
        if (r == 0) break;
        b += r;
        buflen -= r;
    }
    buflen = 0;
}

static void outch(const char x) {
    if (buflen >= (long long) sizeof buf) flush();
    buf[buflen++] = x;
}

static void outsescape(const char *x, int flaglf) {

    long long i;

    for (i = 0; x[i]; ++i) {
        if (x[i] == '\n') {
            if (flaglf) { outch('\n'); }
            else {
                outch('\\');
                outch('n');
            }
        }
        else if (x[i] == '\r') {
            outch('\\');
            outch('r');
        }
        else if (x[i] == '\t') {
            outch('\\');
            outch('t');
        }
        else if (x[i] < 32 || x[i] > 126) {
            outch('\\');
            outch('x');
            outch("0123456789abcdef"[(x[i] >> 4) & 15]);
            outch("0123456789abcdef"[(x[i] >> 0) & 15]);
        }
        else { outch(x[i]); }
    }
}
#define outs(x) outsescape((x), 1)

static char *numtostr(char *strbuf, long long strbuflen, long long n,
                      long long cnt) {

    long long len = 0;
    unsigned long long n1, n2;
    int flagsign = 0;

    if (cnt > strbuflen - 1) cnt = strbuflen - 1;

    n1 = n2 = (unsigned long long) n;
    if (n < 0) {
        n1 = -n1;
        n2 = -n2;
        flagsign = 1;
    }

    do {
        n1 /= 10;
        ++len;
    } while (n1);
    if (flagsign) ++len;
    strbuf += len;
    if (cnt > len) strbuf += cnt - len;
    *strbuf = 0;

    do {
        *--strbuf = '0' + (n2 % 10);
        n2 /= 10;
    } while (n2);
    while (cnt > len) {
        *--strbuf = '0';
        --cnt;
    }
    if (flagsign) *--strbuf = '-';

    return strbuf;
}

static void outnum(long long n, long long cnt) {

    char numbuf[STATICBUFSIZE];
    outs(numtostr(numbuf, sizeof numbuf, n, cnt));
}

/*
 * log_9_ - Emit one formatted log record.
 *
 * The message is composed from up to 9 fragments (s0..s8); the first NULL
 * fragment terminates the list. Depending on current configuration, the record
 * may include time, program name, level, ip, a decoded errno suffix, a source
 * location suffix, and an optional id.
 *
 * A single separator space is inserted before the first printed suffix:
 * - (error)
 * - {file:function:line}
 * - [id]
 *
 * When multiple suffixes are printed, they are adjacent (no extra spaces).
 */
void log_9_(int level, int flagerror, const char *f, unsigned long long l,
            const char *fce, const char *s0, const char *s1, const char *s2,
            const char *s3, const char *s4, const char *s5, const char *s6,
            const char *s7, const char *s8) {
    const char *s[9];
    long long i;
    const char *levelname;
    const char *levelcolor = 0;
    int flagspace = 0;

    if (level > log_level) return;
    if (level >= log_level_TRACING && !log_whitelist_match(f, fce)) return;

    s[0] = s0;
    s[1] = s1;
    s[2] = s2;
    s[3] = s3;
    s[4] = s4;
    s[5] = s5;
    s[6] = s6;
    s[7] = s7;
    s[8] = s8;

    switch (level) {
        case 1:
            if (flagerror == 2) {
                levelname = "bug";
                levelcolor = "[95m"; /* magenta */
            }
            else {
                levelname = "fatal";
                levelcolor = "[91m"; /* bright red */
            }
            break;
        case 2:
            if (flagerror == 1) {
                levelname = "error";
                levelcolor = "[31m"; /* red */
            }
            else if (flagerror == 2) {
                levelname = "warning";
                levelcolor = "[93m"; /* yellow */
            }
            else {
                levelname = "info";
                levelcolor = "[34m"; /* blue */
            }
            break;
        case 3:
            levelname = "debug";
            break;
        case 4:
            levelname = "tracing";
            break;
        default:
            levelname = "unknown";
            break;
    }

    /* time: name: level: ip: message (error){file:function:line}[id] */

    /* color */
    do {
        if (!logcolor) break;
        if (!levelcolor) break;
        outch(27);
        outs(levelcolor);
    } while (0);

    /* 'time:' */
    do {
        struct tm *t;
        int saved_errno = errno;
        struct timeval tv;
        gettimeofday(&tv, (struct timezone *) 0);
        if (!level) break;   /* don't print in usage messages */
        if (!logtime) break; /* don't print when logtime = 0 */

        t = localtime(&tv.tv_sec);
        outnum(t->tm_year + 1900, 4);
        outs("-");
        outnum(t->tm_mon + 1, 2);
        outs("-");
        outnum(t->tm_mday, 2);
        outs(" ");
        outnum(t->tm_hour, 2);
        outs(":");
        outnum(t->tm_min, 2);
        outs(":");
        outnum(t->tm_sec, 2);
        outs(".");
        outnum(tv.tv_usec, 6);
        outs(": ");
        errno = saved_errno;
    } while (0);

    /* 'name:' */
    do {
        if (!level) break;   /* don't print in usage messages */
        if (!logname) break; /* don't print when logname = 0 */
        outsescape(logname, 0);
        outs(": ");
    } while (0);

    /* 'level:' */
    do {
        if (!level) break; /* don't print in usage messages */
        outs(levelname);
        outs(": ");
    } while (0);

    /* 'ip:' */
    do {
        if (!level) break;    /* don't print in usage messages */
        if (!logipstr) break; /* don't print when logipstr = 0 */
        outsescape(logipstr, 0);
        outs(": ");
    } while (0);

    /* 'message' */
    for (i = 0; i < 9 && s[i]; ++i) outsescape(s[i], !level);

    /* '(error)' */
    do {
        if (!level) break;     /* don't print in usage messages */
        if (!errno) break;     /* don't print when errno = 0    */
        if (!flagerror) break; /* don't print when disabled     */
        if (level >= 3) break; /* don't print in debug message  */
        if (!flagspace) outs(" ");
        flagspace = 1;
        outs("(");
        outs(e_str(errno));
        outs(")");
    } while (0);

    /* {file:function:line} */
    do {
        if (!level) break;         /* don't print in usage messages          */
        if (!f) break;             /* don't print when no f                  */
        if (!l) break;             /* don't print when no l                  */
        if (log_level <= 2) break; /* print only when debug verbosity is set */
        if (!flagspace) outs(" ");
        flagspace = 1;
        outs("{");
        outs(f);
        outs(":");
        outs(fce);
        outs(":");
        outnum((long long) l, 0);
        outs("}");
    } while (0);

    /* [id] */
    do {
        if (!level) break;         /* don't print in usage messages     */
        if (log_level <= 1) break; /* don't print in usage, fatal level */
        if (!logid) break;         /* don't print when logid = 0        */
        if (logid[0] == 0) break;  /* don't print when logid = ""       */
        if (!flagspace) outs(" ");
        flagspace = 1;
        outs("[");
        outsescape(logid, 0);
        outs("]");
    } while (0);

    /* color */
    do {
        if (!logcolor) break;
        if (!levelcolor) break;
        outch(27);
        outs("[0m");
    } while (0);

    outs("\n");
    flush();
    return;
}

static char staticbuf[9][STATICBUFSIZE];
static int staticbufcounter = 0;

char *log_str(const void *sv) {
    unsigned long long i;
    const char *s = sv;
    char *x;

    staticbufcounter = (staticbufcounter + 1) % 9;
    x = (char *) staticbuf[staticbufcounter];

    for (i = 0; s[i]; ++i) {
        if (i == STATICBUFSIZE - 4) {
            x[STATICBUFSIZE - 4] = '.';
            x[STATICBUFSIZE - 3] = '.';
            x[STATICBUFSIZE - 2] = '.';
            x[STATICBUFSIZE - 1] = 0;
            return x;
        }
        x[i] = s[i];
    }
    x[i] = 0;
    return x;
}

char *log_ip(const unsigned char *ip) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    if (memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12)) {
        struct sockaddr_in6 sa;
        memcpy(&(sa.sin6_addr), ip, 16);
        inet_ntop(AF_INET6, &(sa.sin6_addr), staticbuf[staticbufcounter],
                  STATICBUFSIZE);
    }
    else {
        struct sockaddr_in sa;
        memcpy(&(sa.sin_addr), ip + 12, 4);
        inet_ntop(AF_INET, &(sa.sin_addr), staticbuf[staticbufcounter],
                  STATICBUFSIZE);
    }
    return staticbuf[staticbufcounter];
}

char *log_port(const unsigned char *port) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    return numtostr(staticbuf[staticbufcounter], STATICBUFSIZE,
                    port[0] << 8 | port[1], 0);
}

char *log_ipport(const unsigned char *ip, const unsigned char *port) {
    char *p;
    long long plen;
    staticbufcounter = (staticbufcounter + 1) % 9;
    p = staticbuf[staticbufcounter];
    if (memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12)) {
        struct sockaddr_in6 sa;
        memcpy(&(sa.sin6_addr), ip, 16);
        p[0] = '[';
        inet_ntop(AF_INET6, &(sa.sin6_addr), p + 1, STATICBUFSIZE - 1);
        plen = strlen(p);
        p[plen] = ']';
        p[plen + 1] = 0;
    }
    else {
        struct sockaddr_in sa;
        memcpy(&(sa.sin_addr), ip + 12, 4);
        inet_ntop(AF_INET, &(sa.sin_addr), p, STATICBUFSIZE);
    }
    plen = strlen(p);
    p[plen] = ':';
    numtostr(p + plen + 1, STATICBUFSIZE - plen - 1, port[0] << 8 | port[1], 0);
    return staticbuf[staticbufcounter];
}

char *log_num(long long num) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    return numtostr(staticbuf[staticbufcounter], STATICBUFSIZE, num, 0);
}
char *log_num0(long long num, long long cnt) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    return numtostr(staticbuf[staticbufcounter], STATICBUFSIZE, num, cnt);
}

static void tohex(char *x, long long xlen, const unsigned char *y,
                  long long ylen) {
    long long i;
    for (i = 0; i < ylen; ++i) {
        if (i == (xlen - 4) / 2) {
            x[2 * i + 0] = '.';
            x[2 * i + 1] = '.';
            x[2 * i + 2] = '.';
            x[2 * i + 3] = 0;
            return;
        }
        x[2 * i + 0] = "0123456789abcdef"[(y[i] >> 4) & 15];
        x[2 * i + 1] = "0123456789abcdef"[(y[i] >> 0) & 15];
    }
    x[2 * i] = 0;
}

char *log_hex(const unsigned char *y, long long ylen) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    tohex(staticbuf[staticbufcounter], STATICBUFSIZE, y, ylen);
    return staticbuf[staticbufcounter];
}

void log_unset_id(void) { logid = 0; }

void log_set_id(const char *id) {

    unsigned long long i;

    for (i = 0; id[i] && i < (sizeof(logidbuf) - 4); ++i) logidbuf[i] = id[i];
    logidbuf[i] = 0;

    if (id[i]) {
        logidbuf[sizeof(logidbuf) - 4] = '.';
        logidbuf[sizeof(logidbuf) - 3] = '.';
        logidbuf[sizeof(logidbuf) - 2] = '.';
        logidbuf[sizeof(logidbuf) - 1] = 0;
    }

    logid = logidbuf;
}
