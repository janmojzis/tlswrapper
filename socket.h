#ifndef _SOCKET_H____
#define _SOCKET_H____

extern int socket_tcp(void);

extern int socket_connect(int, const unsigned char *, const unsigned char *,
                          long long);
extern int socket_connected(int);

#endif
