#ifndef FD_H____
#define FD_H____

#define fd_VERSION "20260408"

extern void fd_close_read(int *);
extern void fd_close_write(int *);
extern void fd_blocking_enable(int);
extern void fd_blocking_disable(int);
extern void fd_coe_enable(int);
extern void fd_coe_disable(int);

#endif
