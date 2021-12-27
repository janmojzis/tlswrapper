#ifndef crypto_scalarmult_curve25519_H
#define crypto_scalarmult_curve25519_H

#define crypto_scalarmult_curve25519_BYTES 32
#define crypto_scalarmult_curve25519_SCALARBYTES 32
extern int crypto_scalarmult_curve25519(unsigned char *, const unsigned char *,
                                        const unsigned char *);
extern int crypto_scalarmult_curve25519_base(unsigned char *,
                                             const unsigned char *);

#endif
