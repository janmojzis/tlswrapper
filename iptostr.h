#ifndef _IPTOSTR_H____
#define _IPTOSTR_H____

#include <arpa/inet.h>

#define IPTOSTR_LEN INET6_ADDRSTRLEN

extern char *iptostr(char *, const unsigned char *);

#endif
