#ifndef _JAIL_H____
#define _JAIL_H____

#include <poll.h>

extern int jail_droproot(void);
extern int jail(const char *);
extern int jail_poll(struct pollfd *, nfds_t, int);

#endif
