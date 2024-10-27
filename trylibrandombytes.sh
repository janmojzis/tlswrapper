#!/bin/sh

cleanup() {
  ex=$?
  rm -f try try.c
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

(
  echo '#include <randombytes.h>'
  echo ''
  echo 'static unsigned char buf[1024];'
  echo ''
  echo ''
  echo 'int main(void) {'
  echo '    randombytes(buf, sizeof buf);'
  echo '    return buf[0];'
  echo '}'
) > try.c

if [ x"${CC}" = x ]; then
  echo '$CC not set'
  exit 1
fi

${CC} -o try try.c -lrandombytes
if [ $? -eq 0 ]; then
  echo "librandombytes detected"
  exit 0
else
  echo "librandombytes not detected"
  exit 1
fi
