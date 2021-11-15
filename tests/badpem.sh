#!/bin/sh
set -e

rm -f tlswrapper-loadpem
ln -s ../tlswrapper tlswrapper-loadpem

cleanup() {
  ex=$?
  rm -f tlswrapper-loadpem badpem.out
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

(
  (
    echo 'badpem01.pem test public-part and secret part, extra string R'
    echo 'badpem02.pem test public-part and secret part, unfinished PEM object'
    echo 'badpem03.pem test public-part and secret part, too many PEM objects'
    echo 'badpem04.pem test public-part and secret part, CRLF'
    echo 'badpem05.pem test public-part and secret part, unsupported curve seck384r1'
  ) | (
    while read name comment; do
      echo "badpem: ${comment}" >&2
      ./tlswrapper-loadpem -pi "${name}" && exit 111
      echo
    done
  ) 
) > badpem.out
cmp badpem.out badpem.exp || diff -Nur badpem.exp badpem.out
