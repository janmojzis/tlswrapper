#!/bin/sh
set -e

(
  (
    echo 'okpem00.pem # public-part only'
    echo 'okpem01.pem # public-part and secret part, CR only'
    echo 'okpem02.pem # public-part and secret part, CR only, no newline at the end'
    echo 'okpem03.pem # public-part and secret part, LF only'
    echo 'okpem04.pem # public-part and secret part, CRLF only'
    echo 'okpem05.pem # public-part and secret part, extra newlines'
  ) | (
    while read name comment; do
      echo "${comment}"
      ./testpemload "${name}"
      echo
    done
  ) 
) > okpem.out
cmp okpem.out okpem.exp || diff -Nur okpem.exp okpem.out
