#ifndef _JAIL_H____
#define _JAIL_H____

#include <poll.h>

extern int jail(const char *, const char *, int);
#define jail_droppriv(x) jail((x), 0, 0)

extern int jail_poll(struct pollfd *, nfds_t, int);

#endif
