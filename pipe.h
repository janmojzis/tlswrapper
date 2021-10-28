#ifndef _PIPE_H____
#define _PIPE_H____

extern int pipe_write(int, const void *, long long);
extern int pipe_writefn(int, const char *, const char *);
extern int pipe_writeerrno(int);

extern int pipe_readall(int, void *, size_t);
extern int pipe_readmax(int, void *, size_t *);
extern void *pipe_readalloc(int, size_t *);

#endif
