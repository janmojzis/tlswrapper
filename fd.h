#ifndef FD_H____
#define FD_H____

#define fd_VERSION "20260415"

extern long long fd_read_(int, void *, long long);
extern long long fd_read(const char *, int, void *, long long);
extern long long fd_write_(int, const void *, long long);
extern long long fd_write(const char *, int, const void *, long long);

extern void fd_close_read(const char *, int *);
extern void fd_close_write(const char *, int *);
extern void fd_blocking_enable(int);
extern void fd_blocking_disable(int);
extern void fd_coe_enable(int);
extern void fd_coe_disable(int);

#endif
