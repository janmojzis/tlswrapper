#ifndef _SIO_H____
#define _SIO_H____

typedef struct sio {
  int fd;
  char *buf;
  long long bufsize;
  long long buflen;
  long long (*op)(int, void *, long long);
} sio;

extern void sio_init(sio *, long long (*)(int, void *, long long), int, char *, long long);
#define sio_INIT(op, fd, buf, len) { (fd), (buf), (len), 0, (op) }

/* write */
extern long long sio_write(int, void *, long long);
extern int sio_flush(sio *);
extern int sio_puts(sio *, const char *);
extern int sio_putch(sio *, char);

/* read */
extern long long sio_read(int, void *, long long);
extern long long sio_getch(sio *, char *);

#endif
