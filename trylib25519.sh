#!/bin/sh

if [ x"${CC}" = x ]; then
  echo '$CC not set'
  exit 1
fi

cleanup() {
  ex=$?
  rm -f trylib25519 trylib25519.c
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

(
  echo '#include <lib25519.h>'
  echo ''
  echo 'static unsigned char k[lib25519_dh_BYTES];'
  echo 'static unsigned char pk[lib25519_dh_PUBLICKEYBYTES];'
  echo 'static unsigned char sk[lib25519_dh_SECRETKEYBYTES];'
  echo ''
  echo ''
  echo 'int  main(void) {'
  echo '    lib25519_dh_keypair(pk,sk);'
  echo '    lib25519_dh(k,pk,sk);'
  echo '}'
) > trylib25519.c

${CC} -o trylib25519 trylib25519.c -l25519
if [ $? -eq 0 ]; then
  echo "lib25519 detected"
  exit 0
else
  echo "lib25519 not detected"
  exit 1
fi
