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

  echo "opts test begin"
  ./opts.sh
  echo "opts test end"
  echo
)

echo "all tests passed"
exit 0
