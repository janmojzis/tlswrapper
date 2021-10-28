#ifndef crypto_scalarmult_x448_H
#define crypto_scalarmult_x448_H

#define crypto_scalarmult_x448_BYTES 56
#define crypto_scalarmult_x448_SCALARBYTES 56
extern int crypto_scalarmult_x448(unsigned char *, const unsigned char *, const unsigned char *);
extern int crypto_scalarmult_x448_base(unsigned char *, const unsigned char *);

#endif
