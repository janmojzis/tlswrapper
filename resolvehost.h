#ifndef _RESOLVEHOST_H____
#define _RESOLVEHOST_H____

extern long long resolvehost(unsigned char *, long long, const char *);

extern int resolvehost_init(void);
extern long long resolvehost_do(unsigned char *, long long, const char *);
extern void resolvehost_close(void);

#endif
