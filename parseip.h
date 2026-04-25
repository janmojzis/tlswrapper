#ifndef PARSEIP_H____
#define PARSEIP_H____

#define parseip_VERSION "20260329"

extern int parseip4_(unsigned char *, const char *);
extern int parseip6_(unsigned char *, const char *);

extern int parseip(unsigned char *, const char *);

#endif
