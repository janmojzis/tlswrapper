#ifndef PARSENUM_H____
#define PARSENUM_H____

#define parsenum_VERSION "20260329"

extern int parsenum_(long long *, long long, long long, const char *);
extern int parsenum(long long *, long long, long long, const char *);

#define parsenum_MAX ((long long)(((unsigned long long)(-1)) >> 1))
#define parsenum_MIN (-parsenum_MAX - 1)

#endif
