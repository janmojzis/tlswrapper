#!/bin/sh
set -e

rm -f tlswrapper-parseasn1 asn1.out
ln -s ../tlswrapper tlswrapper-parseasn1

cleanup() {
  ex=$?
  rm -f tlswrapper-parseasn1 asn1.out
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT


(
  ./tlswrapper-parseasn1 -vv -d 738498 -i asn1.pem commonName
  ./tlswrapper-parseasn1 -vv -d 738498 -i asn1.pem countryName
  ./tlswrapper-parseasn1 -vv -d 738498 -i asn1.pem localityName
  ./tlswrapper-parseasn1 -vv -d 738498 -i asn1.pem stateOrProvinceName
  ./tlswrapper-parseasn1 -vv -d 738498 -i asn1.pem organizationName
  ./tlswrapper-parseasn1 -vv -d 738498 -i asn1.pem organizationalUnitName
  ./tlswrapper-parseasn1 -vv -d 738498 -i asn1.pem emailAddress
) > asn1.out

cmp asn1.out asn1.exp || diff -Nur asn1.exp asn1.out
