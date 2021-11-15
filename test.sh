#!/bin/sh
set -e

(
  cd tests

  echo "okpem test begin"
  ./okpem.sh
  echo "okpem test end"
  echo

  echo "badpem test begin"
  ./badpem.sh
  echo "badpem test end"
  echo
)

echo "testalloc begin"
./testalloc
echo "testalloc end"
echo

echo "testjail begin"
./testjail
echo "testjail end"
echo

echo "testrandombytes begin"
./testrandombytes
echo "testrandombytes end"
echo

echo "done"
exit 0
