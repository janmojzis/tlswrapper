#ifndef IPTOSTR_H____
#define IPTOSTR_H____

#include <arpa/inet.h>

#define IPTOSTR_LEN INET6_ADDRSTRLEN

extern const char *iptostr(char *, const unsigned char *);

#endif
