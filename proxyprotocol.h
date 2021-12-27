#ifndef _PROXYPROTOCOL_H____
#define _PROXYPROTOCOL_H____

/* clang-format off */
/*
protocol v1 IPv4/IPv6 - max 120
PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255 ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255 65535 65535\r\n

protocol v2 IPv4/IPv6 - max 36
protocol v2 UNIX - max 216 we (we don't support proxy-protocol for UNIX sockets)
*/
/* clang-format on */
#define PROXYPROTOCOL_MAX 128

extern int proxyprotocol_v1_parse(char *, unsigned char *, unsigned char *,
                                  unsigned char *, unsigned char *);
extern int proxyprotocol_v1_get(int, unsigned char *, unsigned char *,
                                unsigned char *, unsigned char *);
extern long long proxyprotocol_v1(char *, long long, unsigned char *,
                                  unsigned char *, unsigned char *,
                                  unsigned char *);

extern long long proxyprotocol_v2(char *, long long, unsigned char *,
                                  unsigned char *, unsigned char *,
                                  unsigned char *);

#endif
