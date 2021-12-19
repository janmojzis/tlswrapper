#!/bin/sh

cleanup() {
  ex=$?
  rm -rf tlswrappernojail testemptycert
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

PATH="./:${PATH}"
export PATH

ln -s tlswrapper-test tlswrappernojail
touch testemptycert


ls testcerts | grep '^badcert-' |\
while read name; do
  tlswrapper-test -qr tlswrappernojail -vf "testcerts/${name}" true 2>&1
  echo $?
done

#echo 'tlswrapper rejects empty PEM cert.'
#tlswrapper-test -qr tlswrappernojail -vf testemptycert true 2>&1
#echo $?; echo
#echo 'tlswrapper rejects unsupported PEM cert.'
#tlswrapper-test -qr tlswrappernojail -vf testcerts/server-ec-prime256v1-ec-secp224r1-unsupported true 2>&1
#echo $?; echo
