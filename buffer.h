#ifndef _BUFFER_H____
#define _BUFFER_H____

typedef struct buffer {
    char *x;
    long long p;
    long long n;
    int fd;
    long long (*op)(int, void *, long long);
} buffer;

#define BUFFER_INSIZE 8192
#define BUFFER_OUTSIZE 8192

/* init */
extern void buffer_init(buffer *, long long (*)(int, void *, long long), int,
                        void *, long long);
#define buffer_INIT(op, fd, buf, len)                                          \
    { (buf), 0, (len), (fd), (op) }

/* write */
extern long long buffer_write(int, void *, long long);
extern int buffer_flush(buffer *);
extern int buffer_put(buffer *, const void *, long long);
extern int buffer_puts(buffer *, const char *);
extern int buffer_putflush(buffer *, const void *, long long);
extern int buffer_putsflush(buffer *, const char *);

#define buffer_PUTC(s, c)                                                      \
    (((s)->n != (s)->p) ? ((s)->x[(s)->p++] = (c), 0)                          \
                        : buffer_put((s), &(c), 1))

/* read */
extern long long buffer_read(int, void *, long long);
extern long long buffer_get(buffer *, void *, long long);
extern long long buffer_feed(buffer *);

#define buffer_PEEK(s) ((s)->x + (s)->n)
#define buffer_SEEK(s, len) (((s)->p -= (len)), ((s)->n += (len)))

#define buffer_GETC(s, ch)                                                     \
    (((s)->p > 0) ? (*(ch) = (s)->x[(s)->n], buffer_SEEK((s), 1), 1)           \
                  : buffer_get((s), (ch), 1))

/* copy */
extern int buffer_copy(buffer *, buffer *);

#endif
