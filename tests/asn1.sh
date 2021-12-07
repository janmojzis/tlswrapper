#!/bin/sh
set -e

rm -f asn1.out

cleanup() {
  ex=$?
  rm -f asn1.out
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT


(
  ../parseasn1 -vv -d 738498 -i asn1.pem commonName
  ../parseasn1 -vv -d 738498 -i asn1.pem countryName
  ../parseasn1 -vv -d 738498 -i asn1.pem localityName
  ../parseasn1 -vv -d 738498 -i asn1.pem stateOrProvinceName
  ../parseasn1 -vv -d 738498 -i asn1.pem organizationName
  ../parseasn1 -vv -d 738498 -i asn1.pem organizationalUnitName
  ../parseasn1 -vv -d 738498 -i asn1.pem emailAddress
) > asn1.out

cmp asn1.out asn1.exp || diff -Nur asn1.exp asn1.out
