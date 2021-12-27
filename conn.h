#ifndef _CONN_H____
#define _CONN_H____

extern int conn_init(long long);
extern int conn(long long timeout, unsigned char *ip, long long iplen,
                unsigned char *port);

#endif
