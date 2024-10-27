#!/bin/sh

cleanup() {
  ex=$?
  rm -f try try.c
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
) > try.c

${CC} -o try try.c -l25519
