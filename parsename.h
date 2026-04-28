#ifndef PARSENAME_H____
#define PARSENAME_H____

#define parsename_VERSION "20260428"
#define parsename_BYTES 256

extern int parsename_(unsigned char *out, const char *str);
extern int parsename(unsigned char *out, const char *str);

#endif
