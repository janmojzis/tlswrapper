#include "randombytes.h"

#ifdef randombytes_getentropy
#include "randombytes.c-01getentropy"
#endif

#ifdef randombytes_devurandom
#include "randombytes.c-02devurandom"
#endif
