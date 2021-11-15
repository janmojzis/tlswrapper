#!/bin/sh
set -e

rm -f tlswrapper-loadpem okpem.out
ln -s ../tlswrapper tlswrapper-loadpem

cleanup() {
  ex=$?
  rm -f tlswrapper-loadpem okpem.out
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

(
  (
    echo 'okpem00.pem test public-part only'
    echo 'okpem01.pem test public-part and secret part, CR only'
    echo 'okpem02.pem test public-part and secret part, CR only, no newline at the end'
    echo 'okpem03.pem test public-part and secret part, LF only'
    echo 'okpem04.pem test public-part and secret part, CRLF'
    echo 'okpem05.pem test public-part and secret part, extra newlines'
  ) | (
    while read name comment; do
      echo "okpem: ${comment}" >&2
      ./tlswrapper-loadpem -pi "${name}"
      echo
    done
  ) 
) > okpem.out
cmp okpem.out okpem.exp || diff -Nur okpem.exp okpem.out
