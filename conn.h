#ifndef CONN_H____
#define CONN_H____

extern int conn_init(long long);
extern int conn(int connfds[2], long long timeout, unsigned char *ip,
                long long iplen, unsigned char *port);

#endif
