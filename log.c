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
 */

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "e.h"
#include "log.h"
#include "randommod.h"

#define STATICBUFSIZE 68 /* space for '64 characters' + '...' + '\0' */
#define LOG_ID_LEN 16    /* generated random log id length */
#define NULLSTR "(null)"

struct node {
    struct node *next;
    char *name;
    long long namelen;
};

static struct node *whitelist_head = 0;

/*
 * log_whitelist_add - Add a file-prefix entry to the tracing whitelist.
 *
 * @name: file name prefix to match
 *
 * Adds one whitelist node. Tracing output is later restricted to
 * source file names that start with one of the registered prefixes.
 *
 * Constraints:
 *   - @name must point to a NUL-terminated string
 *
 * Returns 1 on success and 0 on allocation failure or invalid input.
 */
int log_whitelist_add(const char *name) {

    struct node *node;
    long long len;
    char *copy;

    if (!name) return 0;

    len = (long long) strlen(name);
    copy = (char *) malloc((size_t) len + 1);
    if (!copy) return 0;
    memcpy(copy, name, (size_t) len + 1);

    node = (struct node *) malloc(sizeof(*node));
    if (!node) {
        free(copy);
        return 0;
    }
    node->name = copy;
    node->namelen = len;
    node->next = whitelist_head;
    whitelist_head = node;

    return 1;
}

/*
 * log_whitelist_free - Release all whitelist entries.
 *
 * Walks the linked list, frees each node and its name string,
 * and resets the head pointer.
 */
void log_whitelist_free(void) {

    struct node *node = whitelist_head;
    struct node *next;

    whitelist_head = 0;
    while (node) {
        next = node->next;
        free(node->name);
        free(node);
        node = next;
    }
}

/*
 * log_whitelist_match - Check whether tracing is allowed for a source file.
 *
 * @file: source file name to test
 * @fce:  unused, reserved for future per-function filtering
 *
 * Returns 1 when tracing should be emitted for @file. When no whitelist
 * entries exist, tracing remains enabled for all files. Matching is based
 * only on the source file prefix.
 */
static int log_whitelist_match(const char *file, const char *fce) {

    struct node *node;
    long long filelen;

    (void) fce;
    if (!whitelist_head) return 1;
    if (!file) return 1;

    filelen = (long long) strlen(file);

    for (node = whitelist_head; node; node = node->next) {
        if (node->namelen > filelen) continue;
        if (!memcmp(file, node->name, (size_t) node->namelen)) return 1;
    }
    return 0;
}

/*
 * volatile sig_atomic_t because log_inc_level() and log_dec_level()
 * are used as signal handlers.
 */
volatile sig_atomic_t log_level = log_level_FATAL;
static const char *logname = 0;
static int logtime = 0;
static const char *logipstr = 0;
static char logidbuf[STATICBUFSIZE];
static const char *logid = 0;
static int logcolor = 0;

/*
 * log_set_level - Set the global log verbosity.
 *
 * @level: requested verbosity level
 *
 * Clamps @level to the supported range from usage to tracing.
 */
void log_set_level(int level) {
    log_level = level;
    if (level < log_level_USAGE) log_level = log_level_USAGE;
    if (level > log_level_TRACING) log_level = log_level_TRACING;
}

/*
 * log_inc_level - Raise the global log verbosity by one step.
 *
 * @signal: unused signal number
 *
 * Can be installed as a signal handler. The level saturates at tracing.
 */
void log_inc_level(int signal) {
    sig_atomic_t level;

    (void) signal;
    level = log_level;
    if (level < log_level_TRACING) ++level;
    log_level = level;
}

/*
 * log_dec_level - Lower the global log verbosity by one step.
 *
 * @signal: unused signal number
 *
 * Can be installed as a signal handler. The level saturates at usage.
 */
void log_dec_level(int signal) {
    sig_atomic_t level;

    (void) signal;
    level = log_level;
    if (level > log_level_USAGE) --level;
    log_level = level;
}

/* log_set_name - Set the program name shown in log records. */
void log_set_name(const char *name) { logname = name; }
/* log_set_time - Enable or disable the timestamp prefix. */
void log_set_time(int flag) { logtime = flag; }
/* log_set_color - Enable or disable ANSI color output. */
void log_set_color(int flag) { logcolor = flag; }
/* log_set_ip - Set the IP address shown in log records. */
void log_set_ip(const char *ip) { logipstr = ip; }
/* log_get_id - Return the current log record identifier, or NULL. */
const char *log_get_id(void) { return logid; }

static char buf[256];
static long long buflen = 0;

/*
 * flush - Write the buffered log output to standard error.
 *
 * Retries short-term write interruptions and non-blocking retries. Any
 * remaining buffered bytes are dropped once an unrecoverable write error
 * occurs or write() stops making forward progress.
 */
static void flush(void) {

    char *b = buf;
    long long r;
    int retries = 0;

    while (buflen > 0) {
        r = write(2, b, (unsigned long long) buflen);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (++retries < 64) continue;
            }
            break;
        }
        retries = 0;
        if (r == 0) break;
        b += r;
        buflen -= r;
    }
    buflen = 0;
}

/*
 * outch - Append one character to the internal output buffer.
 *
 * @x: character to append
 *
 * Flushes the buffer first when it is already full.
 */
static void outch(const char x) {
    if (buflen >= (long long) sizeof buf) flush();
    buf[buflen++] = x;
}

/*
 * outsescape - Emit a string with log escaping rules applied.
 *
 * @x: input string
 * @flaglf: keep literal newlines when non-zero
 *
 * Escapes carriage return, tab, and non-printable bytes. Newlines are
 * either preserved or converted to the two-character sequence "\n".
 */
static void outsescape(const char *x, int flaglf) {

    long long i;

    for (i = 0; x[i]; ++i) {
        unsigned char c = (unsigned char) x[i];
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
        else if (c < 32 || c > 126) {
            outch('\\');
            outch('x');
            outch("0123456789abcdef"[(c >> 4) & 15]);
            outch("0123456789abcdef"[(c >> 0) & 15]);
        }
        else { outch(x[i]); }
    }
}
#define outs(x) outsescape((x), 1)

/*
 * numtostr - Format a signed integer into a caller-supplied buffer.
 *
 * @strbuf: destination buffer
 * @strbuflen: size of @strbuf in bytes
 * @n: number to format
 * @cnt: minimum field width; shorter results are zero-padded on the left
 *
 * Returns a pointer into @strbuf where the formatted string starts.
 * Output is truncated when @cnt exceeds the available buffer space.
 */
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

/*
 * outnum - Emit a decimal number through the buffered output path.
 *
 * @n: number to format
 * @cnt: minimum field width with zero padding
 */
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
    int saved_errno = errno;
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
        struct timeval tv;
        if (!level) break;   /* don't print in usage messages */
        if (!logtime) break; /* don't print when logtime = 0 */

        gettimeofday(&tv, (struct timezone *) 0);
        t = localtime(&tv.tv_sec);
        if (!t) {
            errno = saved_errno;
            break;
        }
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
        if (!level) break;       /* don't print in usage messages */
        if (!saved_errno) break; /* don't print when errno = 0  */
        if (!flagerror) break;   /* don't print when disabled   */
        if (level >= 3) break;   /* don't print in debug/tracing messages */
        if (!flagspace) outs(" ");
        flagspace = 1;
        outs("(");
        outs(log_errno(saved_errno));
        outs(")");
    } while (0);

    /* {file:function:line} */
    do {
        if (!level) break;         /* don't print in usage messages          */
        if (!f) break;             /* don't print when no f                  */
        if (!fce) break;           /* don't print when no fce                */
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
    errno = saved_errno;
    return;
}

static char staticbuf[9][STATICBUFSIZE];
static int staticbufcounter = 0;

/*
 * log_str - Copy a string into a rotating static log buffer.
 *
 * @sv: input string
 *
 * Returns a pointer to a static buffer containing the input string.
 * Long strings are truncated and suffixed with "...".
 * NULL input returns "(null)".
 *
 * Constraints:
 *   - @sv must point to a NUL-terminated string or be NULL
 */
char *log_str(const void *sv) {
    unsigned long long i;
    const char *s = (const char *) sv;
    char *x;

    if (!sv) {
        staticbufcounter = (staticbufcounter + 1) % 9;
        x = (char *) staticbuf[staticbufcounter];
        memcpy(x, NULLSTR, sizeof NULLSTR);
        return x;
    }

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

/* log_errno - Return a stable log string for an errno value. */
const char *log_errno(int err) { return e_str(err); }

/*
 * log_ip - Format a 16-byte IP address for logging.
 *
 * @ip: IPv6 address or IPv4-mapped IPv6 address
 *
 * Returns a pointer to a rotating static buffer containing either an
 * IPv6 presentation form or a dotted-decimal IPv4 address.
 * NULL input returns "(null)".
 */
char *log_ip(const unsigned char *ip) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    if (!ip) {
        memcpy(staticbuf[staticbufcounter], NULLSTR, sizeof NULLSTR);
        return staticbuf[staticbufcounter];
    }
    if (memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12)) {
        struct sockaddr_in6 sa;
        memcpy(&(sa.sin6_addr), ip, 16);
        if (!inet_ntop(AF_INET6, &(sa.sin6_addr), staticbuf[staticbufcounter],
                       STATICBUFSIZE))
            staticbuf[staticbufcounter][0] = 0;
    }
    else {
        struct sockaddr_in sa;
        memcpy(&(sa.sin_addr), ip + 12, 4);
        if (!inet_ntop(AF_INET, &(sa.sin_addr), staticbuf[staticbufcounter],
                       STATICBUFSIZE))
            staticbuf[staticbufcounter][0] = 0;
    }
    return staticbuf[staticbufcounter];
}

/*
 * log_port - Format a 2-byte network-order port number for logging.
 *
 * @port: big-endian port bytes
 *
 * Returns a pointer to a rotating static buffer containing the decimal
 * port value. NULL input returns "(null)".
 */
char *log_port(const unsigned char *port) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    if (!port) {
        memcpy(staticbuf[staticbufcounter], NULLSTR, sizeof NULLSTR);
        return staticbuf[staticbufcounter];
    }
    return numtostr(staticbuf[staticbufcounter], STATICBUFSIZE,
                    port[0] << 8 | port[1], 0);
}

/*
 * log_ipport - Format an address and port pair for logging.
 *
 * @ip: IPv6 address or IPv4-mapped IPv6 address
 * @port: big-endian port bytes
 *
 * Returns a pointer to a rotating static buffer containing either
 * "[ipv6]:port" or "ipv4:port". NULL input returns "(null)".
 */
char *log_ipport(const unsigned char *ip, const unsigned char *port) {
    char *p;
    long long plen;
    staticbufcounter = (staticbufcounter + 1) % 9;
    p = staticbuf[staticbufcounter];
    if (!ip || !port) {
        memcpy(p, NULLSTR, sizeof NULLSTR);
        return p;
    }
    if (memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12)) {
        struct sockaddr_in6 sa;
        memcpy(&(sa.sin6_addr), ip, 16);
        p[0] = '[';
        if (!inet_ntop(AF_INET6, &(sa.sin6_addr), p + 1, STATICBUFSIZE - 1))
            p[1] = 0;
        plen = (long long) strlen(p);
        p[plen] = ']';
        p[plen + 1] = 0;
    }
    else {
        struct sockaddr_in sa;
        memcpy(&(sa.sin_addr), ip + 12, 4);
        if (!inet_ntop(AF_INET, &(sa.sin_addr), p, STATICBUFSIZE)) p[0] = 0;
    }
    plen = (long long) strlen(p);
    p[plen] = ':';
    numtostr(p + plen + 1, STATICBUFSIZE - plen - 1, port[0] << 8 | port[1], 0);
    return staticbuf[staticbufcounter];
}

/*
 * log_num - Format a signed integer for logging.
 *
 * @num: number to format
 *
 * Returns a pointer to a rotating static buffer containing the decimal
 * representation of @num.
 */
char *log_num(long long num) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    return numtostr(staticbuf[staticbufcounter], STATICBUFSIZE, num, 0);
}

/*
 * log_num0 - Format a signed integer with zero padding for logging.
 *
 * @num: number to format
 * @cnt: minimum field width with zero padding
 *
 * Returns a pointer to a rotating static buffer containing the decimal
 * representation of @num.
 */
char *log_num0(long long num, long long cnt) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    return numtostr(staticbuf[staticbufcounter], STATICBUFSIZE, num, cnt);
}

/*
 * tohex - Encode bytes as lowercase hexadecimal into a caller buffer.
 *
 * @x: destination string buffer
 * @xlen: size of @x in bytes
 * @y: input bytes
 * @ylen: number of bytes to encode
 *
 * Writes a NUL-terminated hexadecimal string. Long output is truncated
 * and replaced with a trailing "...".
 */
static void tohex(char *x, long long xlen, const unsigned char *y,
                  long long ylen) {
    long long i;
    if (xlen <= 4) return;
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

/*
 * log_hex - Format bytes as hexadecimal for logging.
 *
 * @y: input bytes
 * @ylen: number of bytes to encode
 *
 * Returns a pointer to a rotating static buffer containing lowercase
 * hexadecimal output, truncated with "..." when needed.
 * NULL input returns "(null)".
 */
char *log_hex(const unsigned char *y, long long ylen) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    if (!y) {
        memcpy(staticbuf[staticbufcounter], NULLSTR, sizeof NULLSTR);
        return staticbuf[staticbufcounter];
    }
    if (ylen <= 0) {
        staticbuf[staticbufcounter][0] = 0;
        return staticbuf[staticbufcounter];
    }
    tohex(staticbuf[staticbufcounter], STATICBUFSIZE, y, ylen);
    return staticbuf[staticbufcounter];
}

/* log_unset_id - Clear the log record identifier. */
void log_unset_id(void) { logid = 0; }

/*
 * log_set_id - Set the optional log record identifier.
 *
 * @id: identifier string to copy, or NULL to autoselect one
 *
 * Copies @id into a fixed internal buffer. When @id is NULL, the function
 * first tries LOG_ID from the environment and otherwise generates a fresh
 * random identifier of length LOG_ID_LEN, then exports the resulting
 * value back to LOG_ID. Overlong identifiers are truncated and suffixed
 * with "...".
 *
 * Constraints:
 *   - non-NULL @id must point to a NUL-terminated string
 */
void log_set_id(const char *id) {

    const char chars[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    unsigned long long i, len;

    if (!id) id = getenv("LOG_ID");
    if (!id) {
        len = sizeof(logidbuf) - 1;
        if (len > LOG_ID_LEN) len = LOG_ID_LEN;
        for (i = 0; i < len; ++i) {
            logidbuf[i] = chars[randommod((long long) (sizeof(chars) - 1))];
        }
        logidbuf[i] = 0;
        id = logidbuf;
    }

    for (i = 0; id[i] && i < (sizeof(logidbuf) - 1); ++i) logidbuf[i] = id[i];
    logidbuf[i] = 0;

    if (id[i] && sizeof(logidbuf) >= 4) {
        logidbuf[sizeof(logidbuf) - 4] = '.';
        logidbuf[sizeof(logidbuf) - 3] = '.';
        logidbuf[sizeof(logidbuf) - 2] = '.';
        logidbuf[sizeof(logidbuf) - 1] = 0;
    }

    logid = logidbuf;
    (void) setenv("LOG_ID", logid, 1);
}
