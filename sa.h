#ifndef _SA_H____
#define _SA_H____

struct sa {
    unsigned char *p;
    unsigned long long len;
    unsigned long long alloc;
    int error;
};

extern void sa_append(void *, const void *, unsigned long long);

#endif
