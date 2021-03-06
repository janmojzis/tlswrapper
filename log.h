#ifndef _LOG_H____
#define _LOG_H____

extern void log_name(const char *);
extern void log_ip(const char *);
extern void log_id(const char *);
extern void log_level(int);
extern void log_time(int);
extern void log_limit(long long);

extern const char *log_getid(void);

extern char *logip(unsigned char *);
extern char *logport(unsigned char *);
extern char *lognum(long long);
extern char *lognum0(long long, long long);
extern char *loghex(unsigned char *, long long);

extern void log_9_(int, int, const char *, unsigned long long, const char *,
                   const char *, const char *, const char *, const char *,
                   const char *, const char *, const char *, const char *);

/* usage */
#define log_u(a, b, c, d, e, f, g, h, i, j, k)                                 \
    log_9_(0, 0, a, b, c, d, e, f, g, h, i, j, k)
#define log_u9(a, b, c, d, e, f, g, h, i)                                      \
    log_u(__FILE__, __LINE__, a, b, c, d, e, f, g, h, i)
#define log_u8(a, b, c, d, e, f, g, h) log_u9(a, b, c, d, e, f, g, h, 0)
#define log_u7(a, b, c, d, e, f, g) log_u8(a, b, c, d, e, f, g, 0)
#define log_u6(a, b, c, d, e, f) log_u7(a, b, c, d, e, f, 0)
#define log_u5(a, b, c, d, e) log_u6(a, b, c, d, e, 0)
#define log_u4(a, b, c, d) log_u5(a, b, c, d, 0)
#define log_u3(a, b, c) log_u4(a, b, c, 0)
#define log_u2(a, b) log_u3(a, b, 0)
#define log_u1(a) log_u2(a, 0)

/* fatal */
#define log_f(a, b, c, d, e, f, g, h, i, j, k)                                 \
    log_9_(1, 1, a, b, c, d, e, f, g, h, i, j, k)
#define log_f9(a, b, c, d, e, f, g, h, i)                                      \
    log_f(__FILE__, __LINE__, a, b, c, d, e, f, g, h, i)
#define log_f8(a, b, c, d, e, f, g, h) log_f9(a, b, c, d, e, f, g, h, 0)
#define log_f7(a, b, c, d, e, f, g) log_f8(a, b, c, d, e, f, g, 0)
#define log_f6(a, b, c, d, e, f) log_f7(a, b, c, d, e, f, 0)
#define log_f5(a, b, c, d, e) log_f6(a, b, c, d, e, 0)
#define log_f4(a, b, c, d) log_f5(a, b, c, d, 0)
#define log_f3(a, b, c) log_f4(a, b, c, 0)
#define log_f2(a, b) log_f3(a, b, 0)
#define log_f1(a) log_f2(a, 0)

/* error */
#define log_e(a, b, c, d, e, f, g, h, i, j, k)                                 \
    log_9_(2, 1, a, b, c, d, e, f, g, h, i, j, k)
#define log_e9(a, b, c, d, e, f, g, h, i)                                      \
    log_e(__FILE__, __LINE__, a, b, c, d, e, f, g, h, i)
#define log_e8(a, b, c, d, e, f, g, h) log_e9(a, b, c, d, e, f, g, h, 0)
#define log_e7(a, b, c, d, e, f, g) log_e8(a, b, c, d, e, f, g, 0)
#define log_e6(a, b, c, d, e, f) log_e7(a, b, c, d, e, f, 0)
#define log_e5(a, b, c, d, e) log_e6(a, b, c, d, e, 0)
#define log_e4(a, b, c, d) log_e5(a, b, c, d, 0)
#define log_e3(a, b, c) log_e4(a, b, c, 0)
#define log_e2(a, b) log_e3(a, b, 0)
#define log_e1(a) log_e2(a, 0)

/* warning */
#define log_w(a, b, c, d, e, f, g, h, i, j, k)                                 \
    log_9_(2, 2, a, b, c, d, e, f, g, h, i, j, k)
#define log_w9(a, b, c, d, e, f, g, h, i)                                      \
    log_w(__FILE__, __LINE__, a, b, c, d, e, f, g, h, i)
#define log_w8(a, b, c, d, e, f, g, h) log_w9(a, b, c, d, e, f, g, h, 0)
#define log_w7(a, b, c, d, e, f, g) log_w8(a, b, c, d, e, f, g, 0)
#define log_w6(a, b, c, d, e, f) log_w7(a, b, c, d, e, f, 0)
#define log_w5(a, b, c, d, e) log_w6(a, b, c, d, e, 0)
#define log_w4(a, b, c, d) log_w5(a, b, c, d, 0)
#define log_w3(a, b, c) log_w4(a, b, c, 0)
#define log_w2(a, b) log_w3(a, b, 0)
#define log_w1(a) log_w2(a, 0)

/* info */
#define log_i(a, b, c, d, e, f, g, h, i, j, k)                                 \
    log_9_(2, 0, a, b, c, d, e, f, g, h, i, j, k)
#define log_i9(a, b, c, d, e, f, g, h, i)                                      \
    log_i(__FILE__, __LINE__, a, b, c, d, e, f, g, h, i)
#define log_i8(a, b, c, d, e, f, g, h) log_i9(a, b, c, d, e, f, g, h, 0)
#define log_i7(a, b, c, d, e, f, g) log_i8(a, b, c, d, e, f, g, 0)
#define log_i6(a, b, c, d, e, f) log_i7(a, b, c, d, e, f, 0)
#define log_i5(a, b, c, d, e) log_i6(a, b, c, d, e, 0)
#define log_i4(a, b, c, d) log_i5(a, b, c, d, 0)
#define log_i3(a, b, c) log_i4(a, b, c, 0)
#define log_i2(a, b) log_i3(a, b, 0)
#define log_i1(a) log_i2(a, 0)

/* debug */
#define log_d(a, b, c, d, e, f, g, h, i, j, k)                                 \
    log_9_(3, 1, a, b, c, d, e, f, g, h, i, j, k)
#define log_d9(a, b, c, d, e, f, g, h, i)                                      \
    log_d(__FILE__, __LINE__, a, b, c, d, e, f, g, h, i)
#define log_d8(a, b, c, d, e, f, g, h) log_d9(a, b, c, d, e, f, g, h, 0)
#define log_d7(a, b, c, d, e, f, g) log_d8(a, b, c, d, e, f, g, 0)
#define log_d6(a, b, c, d, e, f) log_d7(a, b, c, d, e, f, 0)
#define log_d5(a, b, c, d, e) log_d6(a, b, c, d, e, 0)
#define log_d4(a, b, c, d) log_d5(a, b, c, d, 0)
#define log_d3(a, b, c) log_d4(a, b, c, 0)
#define log_d2(a, b) log_d3(a, b, 0)
#define log_d1(a) log_d2(a, 0)

/* tracing */
#define log_t(a, b, c, d, e, f, g, h, i, j, k)                                 \
    log_9_(4, 1, a, b, c, d, e, f, g, h, i, j, k)
#define log_t9(a, b, c, d, e, f, g, h, i)                                      \
    log_t(__FILE__, __LINE__, a, b, c, d, e, f, g, h, i)
#define log_t8(a, b, c, d, e, f, g, h) log_t9(a, b, c, d, e, f, g, h, 0)
#define log_t7(a, b, c, d, e, f, g) log_t8(a, b, c, d, e, f, g, 0)
#define log_t6(a, b, c, d, e, f) log_t7(a, b, c, d, e, f, 0)
#define log_t5(a, b, c, d, e) log_t6(a, b, c, d, e, 0)
#define log_t4(a, b, c, d) log_t5(a, b, c, d, 0)
#define log_t3(a, b, c) log_t4(a, b, c, 0)
#define log_t2(a, b) log_t3(a, b, 0)
#define log_t1(a) log_t2(a, 0)

#endif
